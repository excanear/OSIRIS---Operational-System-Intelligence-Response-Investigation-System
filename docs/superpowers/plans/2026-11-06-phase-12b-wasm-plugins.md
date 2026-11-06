# Phase 12b — Server-side WASM plugins Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let operators run sandboxed WASM detection and enrichment plugins on every ingested event under a hard per-event budget.

**Architecture:** New server-only crate `osiris-plugin` wraps `wasmtime` (fuel + `StoreLimits`, no imports allowed, ABI v1 with JSON in/out). `IngestContext` gains `plugins: Option<Arc<PluginSet>>`; enrichment runs before `batch_write`, detection plugins after YAML rules, inside the existing `spawn_blocking` closure. Status via `GET /api/v1/plugins` and `osiris plugins status`.

**Tech Stack:** Rust, wasmtime (latest stable major at plan time), `wat` (dev), `sha2` (already in workspace), axum, clap.

**Spec:** `docs/superpowers/specs/2026-11-06-phase-12b-wasm-plugins-design.md`

## Global Constraints

- `osiris-plugin` is server-side only: add it to the `check_forbidden osiris-agent …` list in `tools/check-dep-graph.sh`, and `check_only_internal_deps osiris-plugin osiris-schema`.
- New external deps: `wasmtime` (pin the current stable major in `[workspace.dependencies]`, `default-features = false`, features `["cranelift", "runtime", "std"]` plus whatever that version needs for fuel; never `wasi`), `wat = "1"` (dev-dependency only). Check `cargo search wasmtime` for the newest non-rc version.
- A plugin module may declare **no imports**; ABI exports exactly as spec §5.2: `memory`, `osiris_abi_version() -> i32` (= 1), `osiris_alloc(i32) -> i32`, `osiris_on_event(i32, i32) -> i64` (`(out_ptr << 32) | out_len`, `0` = no output).
- Defaults/limits (verbatim from spec): `fuel_per_event` default 10_000_000, range 1..=1_000_000_000; `memory_max_mib` default 16, range 1..=256; `version` default 1; `enabled` default true; name `[a-z0-9_-]{1,64}` unique; `sha256` 64 lowercase hex required; `max_wasm_stack` 512 KiB; StoreLimits instances 1, tables 1, table_elements 10 000; output ≤ 64 KiB; ≤ 8 alerts, ≤ 16 tags per call; alert `id` `[a-z0-9_]{1,64}`; `reasons` 1–8 non-blank, each ≤ 512 bytes; tag `[a-z0-9_:.-]{1,64}`.
- Alert ids: `rule_id = "plugin:<name>:<id>"`, `rule_version = version`, `rule_content_hash = sha256`, evidence `[event_id]`, timestamp/host_id from the event. Tags stored as `"plugin:<name>:<tag>"`, deduplicated.
- Any over-cap or invalid output discards the whole output of that call (never partially applied).
- Ingest never fails or drops an event because of a plugin. Plugin failure warnings are rate-limited to one per plugin per 60 s and never contain event content.
- No state survives across batches (fresh `Store` + instance per plugin per batch; fresh instance after any trap).
- Everything builds and tests on Windows. CI gates before merge: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `bash tools/check-dep-graph.sh`, console lint/test/build unchanged.
- Commit messages `feat(12b): …` / `test(12b): …` / `docs(12b): …`, ending with the `Co-Authored-By` line the controller provides.

## Review Focus

1. **A plugin that loops forever or recurses without bound**: fuel/stack stop it, the event proceeds, the *next* event in the same batch gets a correct result from a fresh instance. Test in Task 3 (`infinite_loop_is_stopped_and_next_event_still_evaluated`, `recursion_bomb_traps_without_crashing`).
2. **A plugin that grows memory or returns a pointer/length outside its memory** (incl. `out_ptr + out_len` overflowing u32): counted as memory/output failure, no host panic. Test in Task 3 (`memory_bomb_hits_the_cap`, `out_of_bounds_output_is_an_output_failure`, `output_range_overflow_is_an_output_failure`).
3. **A plugin returning unicode/huge/garbage output** (invalid UTF-8, unknown keys, 9 alerts, a 600-byte reason, a tag with a space, a detection plugin returning tags): whole output discarded, counted, nothing stored. Test in Task 3 (`invalid_outputs_are_discarded_whole`, table-driven).
4. **A plugin trying to keep state between batches** (global counter): second batch sees a fresh counter. Test in Task 3 (`no_state_survives_across_batches`).
5. **Zero plugins configured**: no wasmtime `Engine` created, ingest path unchanged, `/api/v1/plugins` returns `{"plugins": []}`. Tests in Task 4 (`ingest_without_plugins_is_unchanged`) and Task 5 (`plugins_endpoint_returns_empty_list_when_none_configured`).

---

## File Structure

```
crates/osiris-plugin/
  Cargo.toml
  src/lib.rs          re-exports
  src/config.rs       PluginConfig, PluginKind, validate_plugins, ConfigError
  src/abi.rs          PluginOutput parsing + validation (pure, no wasmtime)
  src/load.rs         compile, sha256 check, import/export/ABI checks -> LoadedPlugin
  src/run.rs          PluginSet, per-batch instances, fuel/limits, counters, PluginStatus
  src/fixtures.rs     #[cfg(test)] WAT fixtures shared by tests
crates/osiris-detect/src/rule.rs                 reject ':' in rule ids
crates/osiris-server/src/{config.rs,ingest.rs,main.rs}
crates/osiris-api/src/{plugins.rs,auth_middleware.rs,lib.rs}, tests/composed_router_{auth,tenancy}.rs
crates/osiris-cli/src/{main.rs,client.rs}
crates/osiris-e2e-tests/tests/plugins.rs
crates/osiris-bench/src/{main.rs,ingest.rs}
docs/operators-plugins.md, docs/adr/ADR-013-wasm-plugins.md, PERFORMANCE.md, docs/ROADMAP-REMAINING.md
tools/check-dep-graph.sh
```

---

### Task 1: Crate, config validation, rule-id guard, tag matching

**Files:**
- Create: `crates/osiris-plugin/{Cargo.toml,src/lib.rs,src/config.rs}`
- Modify: root `Cargo.toml` (member + workspace deps), `tools/check-dep-graph.sh`, `crates/osiris-detect/src/{rule.rs,eval.rs}`

**Interfaces:**
- Produces:
  - `pub enum PluginKind { Detection, Enrichment }` (serde lowercase).
  - `pub struct PluginConfig { pub name: String, pub kind: PluginKind, pub path: PathBuf, pub sha256: String, pub version: u32, pub fuel_per_event: u64, pub memory_max_mib: u32, pub enabled: bool }` — `Deserialize`, `deny_unknown_fields`, defaults per Global Constraints.
  - `pub struct ConfigError { pub plugin: String, pub message: String }` (`Display`: `plugin <name>: <message>`).
  - `pub fn validate_plugins(cfgs: &[PluginConfig]) -> Result<(), ConfigError>`.
  - `RuleError::ColonInId { origin: String, id: String }` in `osiris-detect`.
  - `osiris-detect` `Operator::Contains` additionally matches when the actual value is a JSON array containing a string equal to the expected string (so a YAML rule `field: tags, op: contains, value: "plugin:x:y"` works — spec §5.3 "so YAML rules can match plugin tags"). String behaviour unchanged.

- [ ] **Step 1: Failing tests** in `config.rs`: `defaults_apply` (YAML with only name/kind/path/sha256 → fuel 10_000_000, memory 16, version 1, enabled true); `rejects_unknown_key`; `rejects_bad_name` (`"Bad Name"`, 65 chars); `rejects_duplicate_name`; `rejects_bad_sha256` (63 chars, uppercase); `rejects_fuel_out_of_range` (0, 1_000_000_001); `rejects_memory_out_of_range` (0, 257). Each error names the plugin. In `rule.rs`: `rule_id_with_colon_is_rejected` (`id: plugin:x:y` → `ColonInId`); existing bundled-rules load test still passes. In `eval.rs`: `contains_matches_a_member_of_a_string_array` (`["a","plugin:x:y"]` contains `"plugin:x:y"` → true; contains `"plugin:x"` → false, exact member match; non-string members ignored).
- [ ] **Step 2: Run** `cargo test -p osiris-plugin` and `cargo test -p osiris-detect` — FAIL.
- [ ] **Step 3: Implement**; add `osiris-plugin` to workspace members, `wasmtime` and `wat` to `[workspace.dependencies]` (crate uses `wasmtime` from Task 2 on; adding it now is fine), dep-graph lines per Global Constraints.
- [ ] **Step 4: Run** both test commands — PASS; `bash tools/check-dep-graph.sh` — exit 0; clippy clean.
- [ ] **Step 5: Commit** `feat(12b): osiris-plugin crate, config validation, rule-id guard, array contains`.

### Task 2: Output parsing and module loading

**Files:**
- Create: `crates/osiris-plugin/src/{abi.rs,load.rs,fixtures.rs}`

**Interfaces:**
- Consumes: `PluginConfig`, `PluginKind`, `ConfigError` (Task 1).
- Produces:
  - `pub struct PluginAlert { pub id: String, pub severity: Severity, pub reasons: Vec<String> }`.
  - `pub struct PluginOutput { pub alerts: Vec<PluginAlert>, pub tags: Vec<String> }`.
  - `pub fn parse_output(kind: PluginKind, bytes: &[u8]) -> Result<PluginOutput, String>` — enforces every output rule in Global Constraints; error string never contains the output bytes.
  - `pub struct LoadedPlugin { pub config: PluginConfig, /* InstancePre or Module + Engine handle */ }` and `pub fn load_plugin(engine: &wasmtime::Engine, cfg: &PluginConfig) -> Result<LoadedPlugin, ConfigError>`.
  - `pub fn new_engine() -> wasmtime::Engine` (fuel on, `max_wasm_stack` 512 KiB).
  - `#[cfg(test)] pub mod fixtures` with `fn wasm(name) -> Vec<u8>` building WAT for: `detect_nc` (alert `{"id":"nc_seen","severity":"HIGH","reasons":["process is nc"]}` when input contains `"name":"nc"`, else `0`), `tagger` (always `{"tags":["seen"]}`), `infinite_loop`, `memory_bomb`, `recursion_bomb`, `oob_output`, `overflow_output` (`out_ptr = 0xFFFF_FFF0`, `out_len = 0x20`), `fixed_output(json: &str)` (returns a constant JSON), `with_import`, `abi_v2`, `missing_alloc`, `counter` (returns `{"tags":["n<k>"]}` where k increments per call in a global).

- [ ] **Step 1: Failing tests**:
  - `abi.rs`: `parses_alerts_and_tags`, `invalid_outputs_are_rejected` (table: invalid UTF-8, not an object, unknown key, 9 alerts, 17 tags, reason of 513 bytes, 9 reasons, blank reason, bad id `Has-Caps`, tag `a b`, detection with tags, enrichment with alerts, unknown severity, > 64 KiB).
  - `load.rs`: `loads_a_valid_module`, `rejects_sha256_mismatch`, `rejects_module_with_import`, `rejects_wrong_abi_version`, `rejects_missing_export`, `rejects_invalid_wasm`, `rejects_unreadable_file` — each `ConfigError.plugin` is the plugin name. Fixtures are written to a tempdir with their real sha256 in the config.
- [ ] **Step 2: Run** `cargo test -p osiris-plugin` — FAIL.
- [ ] **Step 3: Implement.** sha256 over the file bytes (`sha2`), compare to config before compiling; `module.imports().len() > 0` → reject; check export types; call `osiris_abi_version` once in a throwaway store with a small fuel budget.
- [ ] **Step 4: Run** — PASS; clippy clean.
- [ ] **Step 5: Commit** `feat(12b): plugin output parsing and module loading`.

### Task 3: Sandboxed execution, budgets, counters

**Files:**
- Create: `crates/osiris-plugin/src/run.rs`

**Interfaces:**
- Consumes: `LoadedPlugin`, `load_plugin`, `new_engine`, `parse_output`, fixtures (Task 2).
- Produces:
  - `pub struct PluginSet` with `pub fn load(cfgs: &[PluginConfig]) -> Result<PluginSet, ConfigError>` (calls `validate_plugins`, skips `enabled: false` but keeps them in status, creates one `Engine`).
  - `pub fn enrich_batch(&self, events: &mut [CanonicalEvent])` — runs enrichment plugins in config order, appends `plugin:<name>:<tag>` (dedup).
  - `pub fn detect_batch(&self, events: &[CanonicalEvent]) -> Vec<Alert>` — runs detection plugins in config order, builds alerts per Global Constraints.
  - `pub fn status(&self) -> Vec<PluginStatus>`; `PluginStatus` (`Serialize`) fields exactly as spec §5.8: `name, kind, enabled, sha256, calls, alerts, tags, failures_trap, failures_fuel, failures_memory, failures_output, last_failure: Option<String>, last_failure_at: Option<u64>, total_fuel_used`.
  - `pub fn is_empty(&self) -> bool`.
- Behaviour: `PluginSet` is `Send + Sync`; each `*_batch` call creates one `Store` (with `StoreLimits` per Global Constraints) and instance per plugin, reused for that batch; before each event: `set_fuel(fuel_per_event)`; event JSON = `serde_json::to_value(event)` with `raw_event` removed, serialized once per event per batch call; classify failures: fuel exhausted → `failures_fuel`; memory limit / `memory.grow` denied leading to trap or bad output → `failures_memory` when the limiter recorded a denial during the call, else trap → `failures_trap`; parse/bounds errors → `failures_output`. After any failure, drop the instance and instantiate a fresh one for the next event. Counters are atomics; `last_failure` behind a short `Mutex`. Warnings rate-limited per plugin (60 s).

- [ ] **Step 1: Failing tests** (all in `run.rs`, using fixtures + tempdir configs):
  - `detection_plugin_alert_has_prefixed_rule_id` (event with `process.name = "nc"` → 1 alert, `rule_id == "plugin:detect:nc_seen"`, `rule_version == 1`, `rule_content_hash == sha256`, evidence `[event_id]`, severity High; event without nc → 0).
  - `enrichment_adds_prefixed_deduplicated_tags` (run twice on same events → tag `plugin:tag:seen` appears once).
  - `infinite_loop_is_stopped_and_next_event_still_evaluated` (set: `infinite_loop` detection with `fuel_per_event: 100_000` + `detect_nc`; 2 events, second is nc → 1 alert, `failures_fuel == 2` for the loop plugin, wall time < 5 s).
  - `recursion_bomb_traps_without_crashing` (`failures_trap` or `failures_fuel` ≥ 1, no panic).
  - `memory_bomb_hits_the_cap` (`memory_max_mib: 1` → `failures_memory == 1`).
  - `out_of_bounds_output_is_an_output_failure`, `output_range_overflow_is_an_output_failure`.
  - `invalid_outputs_are_discarded_whole` (using `fixed_output` with 9 alerts and with one valid alert + one bad id → 0 alerts, `failures_output` counted).
  - `no_state_survives_across_batches` (`counter` enrichment: two `enrich_batch` calls of 1 event each → both get `plugin:c:n1`).
  - `disabled_plugin_is_not_run_but_listed`.
  - `status_counts_calls_alerts_tags_and_fuel`.
- [ ] **Step 2: Run** `cargo test -p osiris-plugin run` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p osiris-plugin` — PASS; clippy clean.
- [ ] **Step 5: Commit** `feat(12b): sandboxed plugin execution with per-event budgets`.

### Task 4: Server wiring

**Files:**
- Modify: `crates/osiris-server/{Cargo.toml,src/config.rs,src/ingest.rs,src/main.rs}`, every `IngestContext { … }` literal (`grep -rn "IngestContext {" crates`).

**Interfaces:**
- Consumes: `PluginSet::{load, enrich_batch, detect_batch, is_empty, status}` (Task 3).
- Produces: `ServerConfig.plugins: Vec<osiris_plugin::PluginConfig>` (`#[serde(default)]`, validated in `ServerConfig::load` via `validate_plugins`, mapped to `ConfigError`); `IngestContext.plugins: Option<Arc<osiris_plugin::PluginSet>>` (existing literals get `None`).
- Ingest closure order (spec §5.4): owner check → `plugins.enrich_batch(&mut events)` → `batch_write` → YAML `evaluate_batch` → `alerts.extend(plugins.detect_batch(&events))` → existing writes/risk/export unchanged. `main.rs`: if `config.plugins` non-empty, `PluginSet::load` (error → `eprintln!` + exit 1), one `info!` per plugin (name, kind, sha256 prefix 12 chars, enabled); keep an `Arc` clone for the API (Task 5).

- [ ] **Step 1: Failing tests** in `ingest.rs` (write fixture wasm via `osiris_plugin`'s test-support — expose fixtures to other crates behind a `test-support` cargo feature on `osiris-plugin`, enabled only in `[dev-dependencies]`):
  - `enrichment_tags_are_stored_and_visible_to_yaml_rules` (tagger plugin + YAML rule matching `tags` contains `plugin:tag:seen` → stored event has the tag and the YAML alert fires).
  - `plugin_alert_is_stored_and_exported` (detect_nc + 12a `RecordingExporter` hub → alert in storage with `plugin:` rule id and offered to the hub).
  - `a_failing_plugin_never_fails_ingest` (infinite_loop with small fuel → `ingest` returns Ok, events stored).
  - `ingest_without_plugins_is_unchanged` (Review Focus 5).
  - `config.rs`: `loads_a_config_with_plugins`, `rejects_an_invalid_plugin_at_load`.
- [ ] **Step 2: Run** `cargo test -p osiris-server` — FAIL.
- [ ] **Step 3: Implement**, update all `IngestContext` literals.
- [ ] **Step 4: Run** `cargo build -p osiris-cli -p osiris-server -p osiris-agent` then `cargo test --workspace` — PASS; clippy clean; dep-graph exit 0.
- [ ] **Step 5: Commit** `feat(12b): run plugins in ingest`.

### Task 5: Status API, CLI and in-process end-to-end test

**Files:**
- Create: `crates/osiris-api/src/plugins.rs`, `crates/osiris-e2e-tests/tests/plugins.rs`
- Modify: `crates/osiris-api/{Cargo.toml,src/lib.rs,src/auth_middleware.rs}`, `crates/osiris-api/tests/composed_router_{auth,tenancy}.rs`, `crates/osiris-server/src/main.rs` (merge router before `auth_gate`, next to `build_exporters_router`), `crates/osiris-cli/src/{main.rs,client.rs}`

**Interfaces:**
- Consumes: `PluginSet::status`, `IngestContext.plugins` (Task 4).
- Produces: `pub struct PluginsState { pub plugins: Option<Arc<osiris_plugin::PluginSet>> }`, `pub fn build_plugins_router(state: PluginsState) -> Router` → `GET /api/v1/plugins` `200 {"plugins": [PluginStatus…]}`; `min_role_for` maps `/api/v1/plugins` → `Role::Admin` (mirror the exporters line); CLI `osiris plugins status [--json]`, `pub fn format_plugins_table(body: &serde_json::Value) -> String` columns `NAME KIND CALLS ALERTS TAGS FAILURES LAST_FAILURE` where `FAILURES` = sum of the four failure counters, control characters in `LAST_FAILURE` sanitized like `format_exporters_table`.

- [ ] **Step 1: Failing tests**: `plugins_endpoint_returns_empty_list_when_none_configured`; composed-router `plugins_endpoint_requires_platform_admin` (anon 401, Viewer 403, Analyst 403, Admin 200) and `tenant_admin_cannot_read_plugins` (403); `format_plugins_table_sums_failures`; CLI parse test for `plugins status` and `--json`; e2e `plugin_alert_reaches_storage_api_and_exporter` (in-process like `tests/exporters.rs`: detect_nc plugin + file exporter; ingest an nc event; within 5 s the export file holds the alert with `rule_id` `plugin:…:nc_seen`, `GET /api/v1/alerts` (admin) lists it, `GET /api/v1/plugins` shows `alerts >= 1`).
- [ ] **Step 2: Run** the new tests — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** binaries build + `cargo test --workspace` — PASS; clippy clean.
- [ ] **Step 5: Commit** `feat(12b): plugins status endpoint and cli`.

### Task 6: Bench, docs, ADR

**Files:**
- Modify: `crates/osiris-bench/src/{main.rs,ingest.rs}`, `crates/osiris-real-linux-tests/src/{stack.rs,render.rs}` (only if the bench needs a `plugins_yaml` stack option — mirror `exporters_yaml`), `PERFORMANCE.md`, `docs/ROADMAP-REMAINING.md`
- Create: `docs/operators-plugins.md`, `docs/adr/ADR-013-wasm-plugins.md`, a no-op plugin for the bench (WAT text committed under `crates/osiris-bench/assets/noop_plugin.wat`, compiled at bench start with `wat`)

- [ ] **Step 1: Bench flag** `osiris-bench ingest --plugins` (one no-op detection plugin returning `0`); run with and without at the rate/duration of the documented ingest bench on this Windows host (label it), 2 alternating runs each; add a "Phase 12b — plugin overhead" section to `PERFORMANCE.md`. Honest numbers, no target.
- [ ] **Step 2: `docs/operators-plugins.md`**: config reference (every field, default, range), ABI v1 (exports, input, output schema, caps), a Rust guest example (`#![no_std]`-free, `cdylib`, `wasm32-unknown-unknown`, `osiris_alloc` via a `Vec` leak, `osiris_on_event` returning packed ptr/len — marked "not built by CI"), budgets and what each failure counter means, rule-id/tag prefixes, ordering (enrichment before storage and rules; detection after rules), no state across batches, status endpoint/CLI, troubleshooting, security model (no imports, sha256 pin, no hot reload).
- [ ] **Step 3: `docs/adr/ADR-013-wasm-plugins.md`** (layout of ADR-012): context (§20), decision (wasmtime core modules, no imports, fuel + StoreLimits, JSON ABI, per-batch instances, sha256 pin), consequences and known gaps (plugins run on resent events too; JSON serialization cost per event; no signatures; global not per-tenant), alternatives rejected (WASI, component model/WIT, Extism, Lua/Rhai embedded scripting, native dylibs).
- [ ] **Step 4: `docs/ROADMAP-REMAINING.md`**: mark 12b done; keep sensor subprocess plugins as future; add debts: plugin signatures, per-tenant plugins, component-model ABI, hot reload.
- [ ] **Step 5: Full gates**: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, binaries build + `cargo test --workspace`, `bash tools/check-dep-graph.sh`, `cd console && npm run lint && npm test && npm run build`. All green.
- [ ] **Step 6: Commit** `docs(12b): plugins operator guide, ADR-013, bench results`.
