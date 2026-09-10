# Phase 6: Detection/Correlation/Risk/Baseline Maturity Implementation Plan

Mirrors the task granularity/process established by phase-5
(`2026-09-10-phase-5-containers-namespaces-cgroups.md`): each task is
write-failing-test -> run to see it fail -> implement -> run to see it pass
-> `cargo build --workspace` + `cargo test --workspace` +
`cargo clippy --workspace --all-targets -- -D warnings` -> commit.

## Global Constraints — scope decisions made for this plan

1. **Storage-backend decision (ARCHITECTURE.md §10.2/§29): SQLite ships
   as-is for this phase; the ClickHouse migration is explicitly deferred,
   not silently skipped.** Confirmed by inspection: there is no
   `benches/`/`benchmarks/` directory or `criterion` dependency anywhere in
   this workspace (checked every `Cargo.toml`), and no production/fleet
   deployment exists — every event volume this repo has ever processed is
   synthetic test/e2e fixture data, orders of magnitude below the
   "single-digit-thousands of writes/sec sustained" threshold §10.2 names as
   SQLite's ceiling. §79's requirement is "benchmark numbers must be
   produced before the ClickHouse migration is executed, not assumed" —
   with no realistic volume to benchmark against, producing a benchmark now
   would be a fabricated number, not a real one. Per §95's "no premature
   infrastructure" and this repo's own Phase 5 precedent (deferring the
   Docker/containerd primary backend rather than force it unverifiable),
   the migration is deferred to whenever real multi-host/fleet volume
   exists to benchmark against. `osiris-storage-clickhouse` is not created
   this phase.

2. **No `osiris-query` (OQL) crate this phase.** ARCHITECTURE.md §29
   explicitly reserves "full OQL" for Phase 7 ("Investigation/Evidence/
   Hunting"). This plan's rule compiler needs AND/OR/NOT/parentheses
   *within one rule's condition tree* (§11.1/§12.3's operator set), which is
   satisfied by a recursive `ConditionNode` tree in `osiris-detect` itself
   — the same relationship §12.3 describes between a general query language
   and a narrower matcher does not require building the general one first.

3. **`osiris-correlate`, `osiris-risk`, `osiris-baseline` are new crates**,
   matching ARCHITECTURE.md §2.2's/§24's/§27's named crate list exactly
   (these names are *already* referenced by `tools/check-dep-graph.sh`,
   confirmed by reading it — the script has been future-proofed for this
   phase since Phase 0). None depend on `osiris-storage` or any sensor/agent
   crate: `osiris-correlate` consumes a small local `EdgeSource` trait (so
   it stays testable without a database), `osiris-risk` depends on
   `osiris-schema` and `osiris-detect` (reusing `field_value`/`matches`/
   `Operator` rather than re-implementing a second field-matcher), and
   `osiris-baseline` owns its own SQLite table via `rusqlite` directly
   (parallel to how `osiris-detect`'s rules and `osiris-storage-sqlite`
   each own their own schema — no new cross-crate storage coupling).

4. **`RiskAnnotation` (frozen in `osiris-schema` since an earlier phase,
   `score: i32`/`reasons: Vec<String>`/`rule_ids: Vec<String>`) is not
   widened.** Per this repo's repeated precedent ("never widen a frozen
   schema type for one call site... solve it in the consuming crate or
   defer"), ARCHITECTURE.md §11.4's exact shape (`score: u8`,
   `reasons: [WeightedReason]`, `related_events`) is added as a **new**
   schema type, `RiskScoreRecord` + `WeightedReason`
   (`crates/osiris-schema/src/risk.rs`), leaving the existing
   `RiskAnnotation`/`CanonicalEvent.risk` untouched. Populating
   `CanonicalEvent.risk` itself would require mutating an already-persisted
   event, which no `Storage` method supports and which this phase does not
   add (events are append-only in practice, per §10.5's spirit) — risk
   scores are queried by `event_id`/`process_key` from their own table
   instead, exactly as `alerts`/`alert_evidence` already are.

5. **`BehavioralChain`s are computed on demand, not persisted.**
   ARCHITECTURE.md §11.3 calls a chain "the structural unit... not a
   separate parallel data structure duplicating the graph" — the graph
   (the `relationships` edge table, newly persisted this phase per
   Constraint 6) is the durable state; a chain is a bounded graph walk over
   it, recomputed per request/per detection evaluation. This avoids a new
   storage table whose staleness would need its own invalidation story.

6. **Relationships become a first-class persisted edge table this phase**,
   closing the gap ARCHITECTURE.md §9.4 describes ("stored as first-class
   edges... the one deliberate denormalization") but which no prior phase
   actually persisted (confirmed by reading `osiris-storage-sqlite`: today
   `CanonicalEvent.relationships` round-trips only inside each event's
   `raw_json` blob, never as queryable rows). `Storage` gains
   `write_relationships`/`query_relationships`; `SqliteStorage` gains a
   `relationships` table keyed by a stable `EntityRef` string encoding
   (`EntityRef::storage_key()`, added to `osiris-schema`) so `from`/`to`
   are indexed and queryable without deserializing every event.

7. **Sequence/window rules are stateful per "subject" entity**, keyed by
   `process_key` when the triggering event carries one, else by
   `session_id`, else the rule never enters sequence state (documented,
   not silently ignored — logged once at rule-load time if a rule sets
   `window`/`sequence` with no way to derive a subject key from the schema,
   though every `sequence` example this phase ships does carry a process).
   State is an in-memory, per-engine `Mutex<HashMap<StateKey, ...>>` (same
   MVP posture as `NsCgroupResolver`'s unbounded cache, Phase 5 Global
   Constraint #8 — eviction/bound hardening is a tracked, not
   newly-introduced, gap) with expiry checked lazily on each `evaluate()`
   call against `window`.

8. **The Detection Engine's public API changes from `&self` to
   `&self` + interior mutability, not `&mut self`.** `DetectionEngine` is
   already held as `Arc<DetectionEngine>` and shared across the ingestion
   loop's `spawn_blocking` closures (confirmed in `osiris-server/src/
   ingest.rs`); sequence state lives behind a `std::sync::Mutex` inside the
   engine so `evaluate`/`evaluate_batch` keep their existing `&self`
   signatures and every existing call site compiles unchanged.

9. **One new detection rule uses the sequence/window grammar**:
   `network_download_then_write.yaml` — `NETWORK_CONNECT` followed within
   `30s` by `FILE_CREATE`/`FILE_WRITE` from the same `process_key`,
   HIGH severity, MITRE T1105 (Ingress Tool Transfer) — this is
   ARCHITECTURE.md §26's own worked trace's curl-downloads-and-writes
   pattern, now expressible as a real stateful rule instead of only a
   narrative example. The existing five rules are left as flat `match:`
   lists (still fully supported — Constraint 10) since none of them need
   boolean grouping to express correctly.

10. **`match:` (flat, implicit-AND) keeps working unmodified**; the new
    `conditions:` field (a `ConditionNode` tree: `Match`/`All`/`Any`/`Not`)
    is additive and mutually exclusive with `match:` (a rule with both is a
    `RuleError::ConflictingConditions` load-time error, not silently
    picking one). This is what makes the AND/OR/NOT/parentheses grammar
    (§12.3) real without rewriting five already-shipped, already-tested
    rule files or their fixtures.

11. **API/CLI additions follow the existing `*_story`/query-param
    pattern exactly** (confirmed by reading `osiris-api/src/lib.rs` and
    `osiris-cli/src/main.rs` in full): `GET /api/v1/graph` (bounded
    subgraph — seed entity + depth + time range, per §12.5's explicit
    "never the full graph" requirement) and `GET /api/v1/risk` (by
    `process_key` or `event_id`) are added to the API; `osiris chain` and
    `osiris risk` are added to the CLI as thin HTTP clients, the same
    relationship every existing subcommand has to the API.

12. **Baseline observation and risk scoring run on the Server's ingestion
    path, after `batch_write`+`write_relationships`, in the same
    `spawn_blocking` closure `ingest.rs` already uses** — matching §26's
    trace step 5's "simultaneously fans the batch out to: Detection...
    Correlation... Baseline" and keeping the privileged/unprivileged
    boundary unchanged (all of this runs Server-side; `osiris-agent` never
    links any of these crates, enforced by `tools/check-dep-graph.sh`,
    extended this phase to check `osiris-baseline` too).

## Task 1: `osiris-schema` — `EntityRef::storage_key`, `RiskScoreRecord`, `WeightedReason`

**Files:** `crates/osiris-schema/src/relationships.rs`,
`crates/osiris-schema/src/risk.rs` (new), `crates/osiris-schema/src/lib.rs`

Add `EntityRef::storage_key(&self) -> String`: a stable, prefix-tagged
string (`"PROCESS:<hex>"`, `"FILE:<host_id>:<inode>:<device_id>"`,
`"IP:<addr>"`, `"DOMAIN:<name>"`, `"USER:<host_id>:<uid>"`,
`"CONTAINER:<id>"`, `"SESSION:<id>"`) used as the indexed `from`/`to`
column in the new `relationships` table (Task 3) and as the `/api/v1/graph`
seed parameter's parse target.

Add `WeightedReason { label: String, weight: i16, evidence: Uuid }` and
`RiskScoreRecord { event_id: Uuid, process_key: Option<ProcessKey>,
host_id: Uuid, timestamp: u64, score: u8, severity: Severity,
reasons: Vec<WeightedReason>, related_events: Vec<Uuid> }` per
ARCHITECTURE.md §11.4 exactly (Global Constraint #4).

Tests: `storage_key` is stable/deterministic and distinct per variant and
per differing field; round-trips `WeightedReason`/`RiskScoreRecord` through
`serde_json`.

**Verify:** `cargo test -p osiris-schema`, `cargo build --workspace`,
`cargo clippy --workspace --all-targets -- -D warnings`. Commit
`feat(schema): add EntityRef::storage_key and the RiskScoreRecord type`.

## Task 2: `osiris-detect` — `ConditionNode` boolean tree (AND/OR/NOT)

**Files:** `crates/osiris-detect/src/rule.rs`, `crates/osiris-detect/src/eval.rs`

Add:
```rust
pub enum ConditionNode {
    Match(Condition),
    All(Vec<ConditionNode>),
    Any(Vec<ConditionNode>),
    Not(Box<ConditionNode>),
}
```
deserialized from YAML shapes `{field,op,value,reason}` / `{all: [...]}` /
`{any: [...]}` / `{not: {...}}}`. `Rule` gains `conditions: Option<ConditionNode>`;
`RuleFile` accepts either `match` (existing flat `Vec<Condition>`) or the new
`conditions`, rejecting a file with both (`RuleError::ConflictingConditions`)
and a file with neither (existing `NoConditions`, now checked against
whichever is present). Add `eval::eval_node(node, event_json) ->
Option<Vec<String>>` (matched reasons, or `None` if it didn't match) —
`Not` never contributes a reason (there is nothing positive to explain);
`All`/`Any` concatenate their children's reasons in order. `evaluate_rule`
in `engine.rs` calls `eval_node` when `conditions` is set, else keeps the
existing flat-list loop unchanged.

Tests: `(A AND B) OR C` and `NOT A` truth tables against synthetic JSON;
a rule mixing `match` and `conditions` fails to load; the reason list for
an `Any` match contains only the branch that actually matched, not both.

**Verify:** same three commands. Commit
`feat(detect): compile AND/OR/NOT condition trees, not just a flat list`.

## Task 3: `osiris-storage` + `osiris-storage-sqlite` — persisted relationships edge table

**Files:** `crates/osiris-storage/src/plan.rs`, `crates/osiris-storage/src/storage.rs`,
`crates/osiris-storage-sqlite/src/sqlite_storage.rs`

Add `RelationshipQueryPlan { entity: Option<EntityRef>, since: Option<u64>,
until: Option<u64>, limit: usize }` (`entity` matches rows where `from` OR
`to` equals its `storage_key()`). Add to `Storage`:
`write_relationships(&self, edges: &[EntityRelationship]) ->
Result<WriteReport, StorageError>` and `query_relationships(&self, plan:
&RelationshipQueryPlan) -> Result<Vec<EntityRelationship>, StorageError>`.
`SqliteStorage` adds table `relationships(from_key TEXT, to_key TEXT,
relation TEXT, event_id TEXT, timestamp INTEGER)` with indexes on
`(from_key)`, `(to_key)`, `(timestamp)`; `write_relationships` is
`INSERT`-only (edges are immutable facts, no dedup key needed beyond
natural idempotency of re-ingesting the same `event_id`'s edges being
harmless for read-only graph queries).

Tests: round-trip write/query by `entity` (both `from`-side and `to`-side
match), `since`/`until` filtering, `limit`.

**Verify:** same three commands. Commit
`feat(storage): persist relationships as a queryable edge table`.

## Task 4: `osiris-correlate` — new crate, graph-walk `BehavioralChain` builder

**Files:** `crates/osiris-correlate/Cargo.toml`, `crates/osiris-correlate/src/lib.rs`,
root `Cargo.toml` (add to `members`), `tools/check-dep-graph.sh` (already
references it — verify, no change needed unless the check list needs
`osiris-correlate` added to the `check_forbidden osiris-agent ...` line)

```rust
pub trait EdgeSource {
    fn edges_for(&self, entity: &EntityRef, since: u64, until: u64) -> Vec<EntityRelationship>;
}
pub struct BehavioralChain { pub seed: EntityRef, pub edges: Vec<EntityRelationship>, pub event_ids: Vec<Uuid> }
pub struct CorrelationEngine { pub max_depth: usize, pub window_ns: u64 }
impl CorrelationEngine {
    pub fn build_chain(&self, source: &impl EdgeSource, seed: EntityRef, seed_time_ns: u64) -> BehavioralChain
}
```
BFS from `seed`, bounded by `max_depth` hops and `[seed_time_ns,
seed_time_ns + window_ns]`, deduplicating edges/entities already visited
(cycle-safe — an `Ip`/`Domain` entity shared by many processes must not
cause unbounded revisits). `event_ids` is the deduplicated, time-ordered
set of every edge's `event_id`, which is what §12.1's `*Story`/§14.4's
`reconstruct_incident` would consume.

Tests (an in-memory `HashMap`-backed `EdgeSource` test double): a
session→process→file+network chain (mirrors §26's worked trace) is fully
reachable within depth/window; an edge outside the time window is
excluded; depth limit truncates a long chain; a diamond (two paths to the
same entity) does not revisit/duplicate.

**Verify:** `cargo test -p osiris-correlate`, `cargo build --workspace`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`bash tools/check-dep-graph.sh`. Commit
`feat(correlate): graph-walk BehavioralChain builder over the relationships edge table`.

## Task 5: `osiris-baseline` — new crate, frequency-table Baseline Engine

**Files:** `crates/osiris-baseline/Cargo.toml`, `crates/osiris-baseline/src/lib.rs`,
root `Cargo.toml`

```rust
pub enum FrequencyKind { ParentChildExec, ProcessNetwork, ProcessDns, UserExe }
pub enum Rarity { New, Rare, Common }
pub struct Observation { pub kind: FrequencyKind, pub key: String, pub rarity: Rarity, pub count: u64 }
pub struct BaselineEngine { /* Mutex<Connection>, rare_threshold */ }
impl BaselineEngine {
    pub fn open(path) -> Result<Self, BaselineError>
    pub fn observe(&self, event: &CanonicalEvent) -> Result<Vec<Observation>, BaselineError>
}
```
Own SQLite table `baseline_frequency(kind TEXT, key TEXT, first_seen
INTEGER, last_seen INTEGER, count INTEGER, PRIMARY KEY(kind, key))`.
`observe` derives zero or more `(kind, key)` pairs from the event
(`ParentChildExec` needs both `process`+`parent_process`;
`ProcessNetwork`/`ProcessDns` need `process`+`network`/`dns`; `UserExe`
needs `user`+`process`), upserts each (increment count, bump `last_seen`,
set `first_seen` only if new), and classifies: `count == 1` after the
upsert -> `New`; `1 < count <= rare_threshold` (default 5, configurable) ->
`Rare`; else `Common`.

Tests: first observation of a pair is `New`; the same pair observed again
is `Common` (count=2 > default... wait, threshold 5, so `Rare` until
count>5) — write the test against the actual threshold, not an assumption;
an event with no `process` (e.g., a bare `AGENT_HEALTH`) yields no
observations, not an error; two different `(parent,child)` pairs are
tracked independently.

**Verify:** `cargo test -p osiris-baseline`, `cargo build --workspace`,
`cargo clippy --workspace --all-targets -- -D warnings`. Commit
`feat(baseline): frequency-table Baseline Engine with NEW/RARE classification`.

## Task 6: `osiris-risk` — new crate, weighted Risk Engine

**Files:** `crates/osiris-risk/Cargo.toml`, `crates/osiris-risk/src/lib.rs`,
`config/risk/weights.yaml` (new), root `Cargo.toml`

```rust
pub struct SeverityWeights { info: i16, low: i16, medium: i16, high: i16, critical: i16 } // loaded from YAML
pub struct RiskEngine { severity_weights: SeverityWeights, baseline_new_weight: i16, baseline_rare_weight: i16, chain_pattern_weight: i16 }
impl RiskEngine {
    pub fn load_from_file(path) -> Result<Self, RiskError>
    pub fn score(&self, event: &CanonicalEvent, alerts: &[Alert], observations: &[osiris_baseline::Observation], chain: Option<&osiris_correlate::BehavioralChain>) -> Option<RiskScoreRecord>
}
```
Weighted reasons: one `WeightedReason` per fired `Alert` (`label` = its
first reason string, `weight` = `severity_weights` lookup on the alert's
severity, `evidence` = the alert's own `alert_id`... note: `WeightedReason.
evidence` is a `Uuid` referencing an *event*, per §11.4's `WeightedReason {
label, weight, evidence: event_id }` — use `alert.evidence()[0]`, the
triggering event); one per `New`/`Rare` baseline observation
(`"Rare executable path"`-style label per Kind, matching §26's own
worked-trace wording where it fits); one fixed-weight reason
(`chain_pattern_weight`, default `+20`) if the chain contains both a
`ConnectedTo` and a `Wrote` edge from the process within the window —
literally §26 step 11's own example, made real. `score` sums weights,
clamps to `0..=100` (`u8`), derives `Severity` from configurable
thresholds, and returns `None` (not a zero-score record) when there is
nothing at all to report — a `RiskScoreRecord` always cites at least one
reason, mirroring `Alert::new`'s own non-emptiness discipline (§11.2's
"never a bare number" carried into "never an empty one" either).

Tests: an event with one HIGH alert and a `New` baseline observation sums
correctly and clamps at 100 on an extreme input; an event with nothing to
report returns `None`; the chain-pattern bonus fires only when both edge
kinds are present from the *same* process within the window.

**Verify:** `cargo test -p osiris-risk`, `cargo build --workspace`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`bash tools/check-dep-graph.sh`. Commit
`feat(risk): weighted, explainable Risk Engine scoring alerts+baseline+chains`.

## Task 7: `osiris-storage` + `osiris-storage-sqlite` — persist/query `RiskScoreRecord`

**Files:** same as Task 3

Add `RiskQueryPlan { process_key: Option<ProcessKey>, event_id: Option<Uuid>,
since: Option<u64>, until: Option<u64>, limit: usize }`, `Storage::
write_risk_scores`/`query_risk_scores`, and a `risk_scores` table +
`risk_score_reasons` join table (mirroring the existing `alerts`/
`alert_evidence` pattern exactly) in `SqliteStorage`.

Tests: round-trip write/query by `process_key` and by `event_id`; reasons
round-trip with their `weight`/`evidence` intact.

**Verify:** same three commands. Commit
`feat(storage): persist and query RiskScoreRecord`.

## Task 8: `osiris-detect` — stateful `sequence`/`window` evaluation

**Files:** `crates/osiris-detect/src/rule.rs`, `crates/osiris-detect/src/engine.rs`

Add `window: Option<u64>` (nanoseconds) and `sequence: Option<Vec<Condition>>`
to `RuleFile`/`Rule` (parsed the same way `match`/`conditions` are; a rule
with `sequence` but no `window` is a load error — an unbounded sequence
window is exactly the resource-bound violation §19.1 prohibits). Add
`DetectionEngine`'s `Mutex<HashMap<(String, String), SequenceState>>`
(keyed by `(rule_id, subject_key)` per Global Constraint #7) tracking
`next_step: usize` and `started_at: u64`. On each `evaluate()` call, for
every rule with a `sequence`: derive the subject key; if the event matches
`sequence[next_step]`, advance; if it matches `sequence[0]` and no state
exists (or the existing state has expired against `window`), start new
state at step 1; on reaching the end, fire the alert (evidence = every
event_id seen across the sequence's steps for that subject) and clear the
state. Expired/incomplete state is lazily dropped, never left to leak
across an unrelated later matching sequence.

Tests (using `network_download_then_write.yaml`, Global Constraint #9):
`NETWORK_CONNECT` then `FILE_CREATE` from the same `process_key` within
30s fires with both event_ids as evidence; the same pair outside the
30s window does not fire; an interleaving unrelated event between the two
steps does not reset progress (sequence steps need not be adjacent);
two different processes each independently mid-sequence do not
cross-contaminate each other's state.

**Verify:** same three commands (`-p osiris-detect`). Commit
`feat(detect): stateful sequence/window rule evaluation`.

## Task 9: `config/rules/network_download_then_write.yaml` — the shipped sequence rule

**Files:** `config/rules/network_download_then_write.yaml`,
`crates/osiris-detect/src/engine.rs` (fixture test, following the exact
"shipped rule loads and fires on its positive fixture only" pattern every
prior phase's rule used)

Tests: positive fixture (connect then write, same process, within window)
fires exactly this rule; negative (different processes, or outside
window) does not; loads together with the other six shipped rules without
cross-firing (`all_seven_shipped_rules_load_together_without_cross_firing`,
extending the existing `all_five_...` test's pattern — it becomes "all
seven" once this task and Task 2's `conditions`-tree rule, if any, land;
if Task 2 adds no new shipped rule, this becomes "all six").

**Verify:** same three commands. Commit
`feat(rules): ship the network-download-then-write sequence rule`.

## Task 10: `osiris-server` — wire Correlation/Baseline/Risk into the ingestion path

**Files:** `crates/osiris-server/src/ingest.rs`, `crates/osiris-server/src/main.rs`

After `batch_write`+`detection_engine.evaluate_batch` (existing), in the
same `spawn_blocking` closure: `storage.write_relationships(&edges)` where
`edges` is every event's `.relationships` flattened; for each event
carrying a `process`, run `baseline_engine.observe(event)`, build a
`BehavioralChain` via a small `Arc<dyn Storage>`-backed `EdgeSource`
adapter (`StorageEdgeSource`, implemented in `ingest.rs` — the one place
`osiris-correlate` and `osiris-storage` meet, avoiding a direct crate
dependency between them per the Global Constraints #3 layering), and call
`risk_engine.score(...)`, writing any resulting `RiskScoreRecord`s via
`storage.write_risk_scores`. `main.rs` constructs `BaselineEngine::open`
and `RiskEngine::load_from_file` alongside the existing `DetectionEngine::
load_from_dir`, with the same "log and continue with an engine that
produces nothing" degrade-not-crash posture `main.rs` already uses for a
missing rules directory (read `main.rs` first to match it exactly).

Tests: the four existing `ingest.rs` tests continue to pass unmodified
(regression proof the new writes don't break the existing shape); one new
test proves an ingested `PROCESS_EXEC` followed by `NETWORK_CONNECT` then
`FILE_CREATE` (same process, within window) ends up with: a relationship
row queryable by the process's `EntityRef`, a fired sequence alert, at
least one baseline `New` observation, and a queryable `RiskScoreRecord`
whose reasons include the chain-pattern bonus — i.e., §26's full trace,
exercised through the real ingestion loop end to end.

**Verify:** same three commands (`-p osiris-server`), plus
`cargo test --workspace` (this task is exactly the kind of cross-crate
wiring whole-workspace review has caught gaps in before, per project
memory). Commit
`feat(server): wire Correlation/Baseline/Risk engines into the ingestion path`.

## Task 11: `osiris-api` — `GET /api/v1/graph`, `GET /api/v1/risk`

**Files:** `crates/osiris-api/src/lib.rs`

`graph_handler(Query{entity, depth, since, until})`: parses `entity` via
the same tagged-string scheme `EntityRef::storage_key` produces (add a
paired `EntityRef::parse_storage_key` in `osiris-schema`, tested for
round-trip with `storage_key` on every variant), runs a bounded
`CorrelationEngine::build_chain` (depth capped server-side at a constant
max regardless of the query param, per §12.5's "never the full graph"),
returns `BehavioralChain` as JSON. `risk_handler(Query{process_key,
event_id})`: delegates to `storage.query_risk_scores`. Both added to
`build_router`'s route list next to the existing `*_story` routes.

Tests: `/api/v1/graph` on a seeded relationship set returns the expected
bounded subgraph and 400s on an unparseable `entity` param; `/api/v1/risk`
filters correctly by `process_key`.

**Verify:** same three commands (`-p osiris-api`). Commit
`feat(api): GET /api/v1/graph and GET /api/v1/risk`.

## Task 12: `osiris-cli` — `osiris chain`, `osiris risk`

**Files:** `crates/osiris-cli/src/client.rs`, `crates/osiris-cli/src/main.rs`

Add `chain_url`/`risk_url` builders in `client.rs` (mirroring
`container_story_url`'s exact shape) and `Command::Chain { entity: String,
depth: Option<usize> }` / `Command::Risk { process_key: Option<String>,
event_id: Option<String> }` in `main.rs`, following the existing
`get()`+format pattern precisely.

Tests: URL-builder unit tests in `client.rs` (matching its existing test
style for `container_story_url`).

**Verify:** same three commands (`-p osiris-cli`). Commit
`feat(cli): osiris chain and osiris risk subcommands`.

## Task 13: `tools/check-dep-graph.sh` — extend for the three new crates

**Files:** `tools/check-dep-graph.sh`

Add `osiris-baseline` to the `check_forbidden osiris-agent ...` line
(`osiris-correlate`/`osiris-risk` are already present, confirmed by
reading the script in Task-0 research — this task only adds the one
missing name so the boundary is actually enforced for every Phase-6
crate, not just two of three).

**Verify:** `bash tools/check-dep-graph.sh` prints `PASSED`. Commit
`chore(ci): enforce dependency boundary for osiris-baseline`.

## Task 14: `osiris-e2e-tests` — prove the full Phase 6 vertical slice end-to-end

**Files:** `crates/osiris-e2e-tests/tests/end_to_end.rs`

One new test, following the file's existing structure/helpers: spins up a
real `SqliteStorage`, a `DetectionEngine` loaded from `config/rules/`
(all seven+ shipped rules), a `BaselineEngine`, a `RiskEngine` loaded from
`config/risk/weights.yaml`, and `osiris-server::ingest`'s real ingestion
loop against a spooled sequence of synthetic events reproducing
ARCHITECTURE.md §26's full worked trace (session login -> bash exec ->
curl exec -> curl connects -> curl writes a file), all sharing one
`process_key`/`session_id`/`host_id` chain. Asserts, querying only through
`Storage`/the built router (no internal engine handles reached into
directly, matching this file's existing "exercise the real path" ethos):
the sequence rule fires; `query_relationships` returns the full multi-hop
chain; `query_risk_scores` returns a record whose score reflects both the
fired alert and the chain-pattern bonus; a `GET /api/v1/graph` request
seeded at the session returns every category (process, network, file) in
one bounded subgraph — the "full data-flow trace this phase must make
genuinely complete" instruction, made an executable assertion.

**Verify:** `cargo test -p osiris-e2e-tests`, then the full gate:
`cargo build --workspace`, `cargo test --workspace`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`bash tools/check-dep-graph.sh`. Commit
`test(e2e): prove the Phase 6 detection/correlation/risk/baseline vertical slice end-to-end`.

## Final steps (after Task 14 is green)

1. Whole-branch self-review: re-read every changed file for cross-file
   provenance mismatches, plan-vs-doc-comment mismatches (recurring lesson
   per project memory), and confirm `tools/check-dep-graph.sh` passes with
   `osiris-agent` never linking `osiris-detect`/`osiris-correlate`/
   `osiris-risk`/`osiris-baseline`/`osiris-storage*`.
2. `cargo test --workspace` and `cargo clippy --workspace --all-targets --
   -D warnings` one final time on the fully assembled branch (not just
   per-task).
3. Merge `phase-6-detection-correlation-risk-baseline` to `master` via a
   real `git merge --ff-only` (or equivalent) from a checkout that is
   `master`'s actual working copy — not `git update-ref` from an isolated
   worktree (the Phase 5 mistake project memory records).
