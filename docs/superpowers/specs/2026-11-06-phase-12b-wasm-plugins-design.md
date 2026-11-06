# Phase 12b — Server-side WASM plugins (design)

Status: design. Marked *(call)* = decided by the assistant under the user's standing
instruction to proceed with the recommended option; everything else comes from
`ARCHITECTURE.md` §20 or `docs/ROADMAP-REMAINING.md`.

Sources: `ARCHITECTURE.md` §20.1–§20.2 (Detection and Enrichment plugins are Server-side
WASM modules, "sandboxed, no ambient authority", "evaluated ... with a bounded execution
budget per event"; Agent-side plugins never load third-party code), roadmap "Fase 12b,
plugins".

## 0. Phase split *(call)*

12b covers only the Server-side WASM plugins (Detection and Enrichment). Sensor plugins as
sandboxed subprocesses (§20.2 option b) stay a future phase: they need the Agent wire
protocol, seccomp and capability work, and share nothing with the WASM host.

## 1. Intent and why

Declarative YAML rules cannot express logic such as "entropy of the command line", "domain
looks algorithmically generated", or a site-specific lookup table compiled into the
plugin. Operators today must fork OSIRIS and write Rust to get that. A plugin lets them
ship such logic as a single `.wasm` file the Server runs on every ingested event, without
being able to touch the host, the network, the database, or other tenants' data — and
without being able to slow ingest beyond a fixed, configured budget.

Success: an operator drops `entropy.wasm` into a directory, adds four lines to
`server.yaml`, restarts, and its alerts appear next to rule alerts in storage, the API,
the console, and the 12a exporters — and a plugin with an infinite loop or a memory bomb
costs at most its budget per event and is visibly counted as failing.

## 2. Goals

1. Two plugin kinds through one ABI:
   - **detection**: per event, returns zero or more alerts (rule id, severity, reasons);
   - **enrichment**: per event, returns zero or more tags added to the event before it is
     stored and before detection runs.
2. Sandbox: a plugin module may import nothing; it gets no WASI, no host functions, no
   clock, no randomness, no I/O. A module declaring any import is rejected at load.
3. Bounded budget per event: fuel (instruction count), linear-memory cap, output size cap,
   alert and tag count caps. Exceeding any of them fails that one plugin call; the event
   and every other plugin and rule are unaffected.
4. Integrity: every configured plugin is pinned by SHA-256 in the config; a mismatch
   refuses startup.
5. Visibility: per-plugin counters through `GET /api/v1/plugins` (platform Admin) and
   `osiris plugins status [--json]`.
6. Zero plugins configured → no runtime created, ingest path unchanged.

## 3. Non-goals

- Sensor, Storage, Exporter or Response plugins.
- Plugins that change any event field other than adding tags.
- Hot reload; plugins load at startup only.
- Signatures / a plugin registry (the SHA-256 pin is the integrity mechanism in 12b).
- A guest SDK crate or a published `wasm32` toolchain in CI. Test fixtures are written in
  WAT; the operator guide shows a Rust guest example that is not built by CI.
- Per-tenant plugins. Plugins are global, like YAML rules.
- Console screens (the status endpoint and CLI are enough; console is Phase 13 UX).

## 4. Anti-goals (failure even if it "works")

- A plugin can stall or crash ingest (infinite loop, deep recursion, huge allocation,
  panic/trap) — budget must be enforced by the runtime, not by plugin cooperation.
- A plugin can read anything outside the single event it was handed, or keep data from
  one batch to the next.
- A plugin alert can be mistaken for a YAML-rule alert or forge another rule's id.
- A plugin failure fails the batch, drops the event, or is silent.
- A plugin's output can inject unbounded data into storage.

## 5. The how: decided parts

### 5.1 Runtime *(call)*

`wasmtime` (pinned major in `[workspace.dependencies]`, default features minimal:
`cranelift`, no `wasi`, no component model needed), new crate `crates/osiris-plugin`,
depending OSIRIS-internally on `osiris-schema` only. Server-only: `tools/check-dep-graph.sh`
forbids `osiris-agent` (and the sensor crates) from depending on it.

Engine config: `consume_fuel(true)`, `max_wasm_stack` 512 KiB, no threads, no SIMD
requirement imposed on the guest beyond wasmtime defaults. Memory limit via
`StoreLimits` (`memory_size` = `memory_max_mib`, `instances` 1, `tables` 1,
`table_elements` 10 000).

### 5.2 ABI (version 1) *(call)*

A plugin is a core WebAssembly module with **no imports** and these exports:

| Export | Type | Meaning |
|---|---|---|
| `memory` | memory | the module's linear memory |
| `osiris_abi_version` | `() -> i32` | must return `1` |
| `osiris_alloc` | `(len: i32) -> i32` | returns a pointer to `len` writable bytes |
| `osiris_on_event` | `(ptr: i32, len: i32) -> i64` | reads the input JSON at `ptr..ptr+len`, returns `(out_ptr << 32) \| out_len` of the output JSON; `0` means "no output" |

Input: UTF-8 JSON of the `CanonicalEvent` exactly as the YAML rule engine sees it
(`serde_json::to_value(event)`), with `raw_event` removed.

Output (UTF-8 JSON object, unknown keys rejected):

```json
{ "alerts": [ { "id": "high_entropy_cmdline", "severity": "HIGH",
                "reasons": ["command line entropy 5.9 > 5.0"] } ],
  "tags":   [ "dga_suspect" ] }
```

- Both keys optional. A detection plugin returning `tags`, or an enrichment plugin
  returning `alerts`, is an output error.
- `id`: `[a-z0-9_]{1,64}`. Severity uses the existing `Severity` wire form. `reasons`:
  1–8 non-blank strings, each ≤ 512 bytes.
- `tags`: each `[a-z0-9_:.-]{1,64}`.

Per-call sequence: `osiris_alloc(len)` → host copies input → `osiris_on_event` → host
bounds-checks `out_ptr..out_ptr+out_len` against memory and reads the output. Fuel is
reset to `fuel_per_event` before `osiris_alloc` and covers both calls.

### 5.3 What the host does with output

- **Alert**: `Alert::new(rule_id = "plugin:<plugin name>:<id>", rule_version =
  plugin config `version` (default 1), rule_content_hash = configured sha256,
  severity, timestamp = event timestamp, host_id = event host_id, reasons, evidence =
  [event_id])`. The `plugin:` prefix is reserved. Today `osiris-detect` only rejects a blank
  rule id, so 12b adds a load-time check in `rule.rs` rejecting any YAML rule id that
  contains `:` *(call)* (no bundled rule in `config/rules` uses `:`, checked); plugin alerts
  can then never collide with rule alerts.
- **Tag**: appended to `event.tags` as `"plugin:<plugin name>:<tag>"`, deduplicated, before
  `batch_write` and before detection, so YAML rules can match plugin tags.
- Caps: output ≤ 64 KiB, ≤ 8 alerts, ≤ 16 tags per call; over a cap → output error, the
  whole output of that call is discarded (never partially applied).

### 5.4 Placement in ingest *(call)*

Inside the existing `spawn_blocking` closure in `IngestContext::ingest`, after the owner
check:

1. Enrichment plugins, in config order, each over every kept event, adding tags.
2. `batch_write` (stores the tags).
3. YAML detection, then detection plugins in config order over every kept event; plugin
   alerts are appended to the rule alerts, so storage, risk/correlation and the 12a
   exporters treat them identically.

Plugins run on new and resent events alike (rules do too; resend dedup of alerts is an
existing debt and out of scope).

### 5.5 Instances and isolation *(call)*

Per plugin, the module is compiled once at startup into an `InstancePre`. For each
**batch**, each plugin gets one fresh `Store` + instance, reused for that batch's events
and dropped at batch end — so no state survives across batches. After any trap or fuel
exhaustion inside a batch, that instance is discarded and a fresh one is created for the
next event of the batch. Calls are synchronous (we are already on a blocking thread).

### 5.6 Failure handling

Per call: trap, fuel exhausted, memory limit hit, bad pointer/length, invalid UTF-8/JSON,
schema violation, or cap exceeded → counted under one of the counters in §5.8, logged
(rate-limited to one warning per plugin per 60 s, naming the plugin and failure kind, never
event content), and the event proceeds as if the plugin returned nothing.

Load time (startup): file unreadable, sha256 mismatch, not a valid module, any import,
missing export, wrong export type, `osiris_abi_version() != 1`, duplicate name → error
naming the plugin; the server exits 1 like other config errors.

### 5.7 Configuration

```yaml
plugins:
  - name: entropy            # [a-z0-9_-]{1,64}, unique
    kind: detection          # detection | enrichment
    path: /etc/osiris/plugins/entropy.wasm
    sha256: 3f5a...           # 64 lowercase hex, required
    version: 1               # u32, default 1, becomes rule_version
    fuel_per_event: 10000000 # default 10_000_000, 1..=1_000_000_000
    memory_max_mib: 16       # default 16, 1..=256
    enabled: true            # default true
```

`ServerConfig.plugins: Vec<PluginConfig>` with `#[serde(default)]`, unknown keys rejected,
validated in `ServerConfig::load`.

### 5.8 Status and counters

`GET /api/v1/plugins` → `{"plugins": [ {name, kind, enabled, sha256, calls,
alerts, tags, failures_trap, failures_fuel, failures_memory, failures_output,
last_failure, last_failure_at, total_fuel_used} ]}`; `last_failure` is the failure
kind plus a short message, never event content. Platform Admin only; tenant-bound
Admin denied (default deny). `osiris plugins status [--json]` prints a table
`NAME KIND CALLS ALERTS TAGS FAILURES LAST_FAILURE`.

## 6. Tests and evidence

- WAT fixtures (compiled with the `wat` dev-dependency): echo-detect (alert when
  `process.name == "nc"`), tagger, infinite loop, memory bomb (`memory.grow` loop),
  recursion bomb, out-of-bounds output pointer, oversized output, invalid JSON output,
  a module with an import, wrong ABI version, stateful counter (proves no state across
  batches).
- Load-time rejections, each named.
- Budget: infinite loop is stopped by fuel and the next event in the same batch still gets
  a correct result from a fresh instance; ingest of a 100-event batch with the
  infinite-loop plugin at default fuel completes (record wall time in the report, assert a
  generous bound).
- Ingest: tags stored and visible to a YAML rule; plugin alert stored with `plugin:`
  prefix and exported by a 12a file exporter; zero plugins → unchanged path.
- API/CLI: role gating on the real composed routers (Viewer/Analyst 403, Admin 200,
  tenant-bound Admin 403), empty list when none configured.
- Bench: `osiris-bench ingest --plugins` with one no-op detection plugin, same rate and
  duration as the documented ingest bench, reported honestly in `PERFORMANCE.md`.
- Docs: `docs/operators-plugins.md` (config, ABI, a Rust guest example, budgets,
  failures, status), `docs/adr/ADR-013-wasm-plugins.md`, roadmap update.

## 7. Constraints

- Windows-buildable and testable (wasmtime supports it); CI gates unchanged: fmt, clippy
  `-D warnings`, `cargo test --workspace`, dep-graph, console lint/test/build.
- Ingest never fails because of a plugin.
- No new network or filesystem access is reachable from guest code.
- Plugin content is never logged.

## 8. Left to the builder

- Exact wasmtime version (current stable at plan time) and feature flags beyond §5.1.
- Internal module layout of `osiris-plugin`.
- Whether to reuse one `serde_json::Value` serialization per event across plugins.
- Wording of log and error messages.
