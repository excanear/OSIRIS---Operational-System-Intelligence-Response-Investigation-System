# ADR-013: Server-side plugins are sandboxed WASM core modules with no imports, a JSON ABI, per-batch instances and a SHA-256 pin

Status: accepted, 2026-11-06 (Phase 12b). Implements ARCHITECTURE.md §20.1/§20.2 (Detection and
Enrichment plugins as server-side WASM; the Agent never loads third-party code). Spec:
`docs/superpowers/specs/2026-11-06-phase-12b-wasm-plugins-design.md`. Operator guide:
`docs/operators-plugins.md`. Measurements: `PERFORMANCE.md`, "Phase 12b - plugin overhead".

## Context

Declarative YAML rules cannot express logic such as the entropy of a command line, whether a domain
looks algorithmically generated, or a site-specific lookup table. Today an operator has to fork
OSIRIS and write Rust. ARCHITECTURE §20 asks for plugins that are "sandboxed, no ambient
authority" and evaluated "with a bounded execution budget per event". The constraints that shape
the design:

- Ingestion is the hot path. A plugin must never stall it, crash it, fail a batch or drop an event.
- Plugin code is untrusted: it must not read anything but the one event it is handed, keep data
  from one batch to the next, forge another rule's alert id or inject unbounded data into storage.
- The Agent must not gain code or dependencies; plugins are a Server concern.
- The workspace builds and tests on Windows with no extra toolchain, and CI does not compile guests.
- Operators must be able to see that a plugin is failing, without the status leaking event content.

## Decision

1. **Wasmtime core modules, one new server-side crate, `osiris-plugin`.** It depends on
   `osiris-schema` among the OSIRIS crates; `tools/check-dep-graph.sh` fails the build if the Agent
   (or a sensor crate) ever depends on it. Wasmtime is pinned in `[workspace.dependencies]` with
   default features off and `cranelift`, `runtime` and `std` on; WASI and the component model are not
   enabled. With no `plugins:` configured, or every plugin disabled, no `Engine` is created and the
   ingest path is unchanged.
2. **No imports.** A module that declares any import is rejected at load. A plugin has no WASI, host
   function, clock, randomness or I/O, so there is no ambient authority to audit.
3. **Fuel and store limits enforce the budget, not the plugin.** Per event: `fuel_per_event` (default
   10 000 000, 1 to 1 000 000 000); one linear memory of at most `memory_max_mib` (default 16, 1 to 256;
   a module declaring more than one memory is rejected, and multi-memory is disabled in the engine); a 512 KiB
   wasm stack; 1 instance, 1 table, 10 000 table elements. Spec §5.1 omitted the `memories(1)` store limit;
   it was added in final review, because wasmtime applies `memory_size` to each memory and a module
   with several memories could otherwise exceed the cap. Output is capped at 64 KiB, 8 alerts and
   16 tags per call. Any violation fails that one call and discards its whole output.
4. **A JSON ABI (version 1).** Exports `memory`, `osiris_abi_version() -> i32`,
   `osiris_alloc(i32) -> i32` and `osiris_on_event(i32, i32) -> i64` (`(out_ptr << 32) | out_len`,
   exactly `0` means no output). The input is the event as the YAML rule engine sees it, minus
   `raw_event`; the output is a strictly validated JSON object of alerts or tags. A JSON ABI needs no
   code generator and can be written in any language that targets core WebAssembly.
5. **A fresh instance per plugin per batch.** One `Store` and instance serve the events of a batch and
   are dropped at its end, so no state survives across batches; after any failure the instance is
   discarded and the next event gets a new one. Each module is compiled once at startup into an
   `InstancePre`, so a fresh instance is cheap.
6. **Alert and tag namespacing.** Alerts get `rule_id = plugin:<name>:<id>`, `rule_version` from the
   config `version` and `rule_content_hash` = the module's SHA-256. Tags are stored as
   `plugin:<name>:<tag>`. The YAML rule loader now rejects any rule id containing `:`, so a rule can
   never collide with a plugin alert.
7. **Placement in ingest.** Enrichment runs after the owner check and before the storage write (so
   stored events and YAML rules see the tags); detection plugins run after the YAML rules, and their
   alerts join the rule alerts, so storage, risk, correlation and the 12a exporters treat them alike.
8. **SHA-256 pin, startup load only.** Every plugin is pinned by digest in the config; a mismatch (or
   any load error: unreadable file, invalid module, import, missing or mistyped export, ABI version
   other than 1, duplicate name) stops the server with exit 1 naming the plugin. No hot reload.
9. **Failures are counted, rate-limited and content-free.** Each failure goes to one of four counters
   (trap, fuel, memory, output). Warnings are limited to one per plugin per 60 s and carry only the
   plugin name, the failure kind and a fixed description. Status is `GET /api/v1/plugins` (platform
   admin only; plugins are global) and `osiris plugins status [--json]`.

## Consequences

- A plugin that loops, recurses without bound, grows memory, returns a pointer outside its memory
  or returns garbage costs at most its budget per event, is visible in the counters, and affects
  neither the event, nor other plugins and rules, nor the next event.
- The overhead of the runtime was measured instead of assumed (PERFORMANCE.md). One no-op plugin
  still pays for serializing every event to JSON and one guest call per event.
- A plugin author gets a small, stable contract and no SDK. The operator guide carries a Rust
  example that CI does not build; the test fixtures are hand-written WAT.
- Plugins read every tenant's events. They are an operator-trusted extension, like the YAML rules,
  not a multi-tenant marketplace.

## Known gaps (deferred)

- **Within-batch sharing.** One instance and one linear memory serve every event of a batch (spec
  §5.5). A malicious or buggy plugin can carry data between events of the same batch, for example
  by emitting an earlier event's fields in a later event's alert reasons or tags. On the spool-tailer
  path (`run_ingestion_context_loop`) a batch is whatever one poll returned and may span hosts and
  therefore tenants, so the leak can cross tenants; on the mTLS path a batch is one Agent's. The
  mitigation is that plugins are operator-installed, SHA-256-pinned code. Per-tenant batch splitting
  is future work (ROADMAP-REMAINING).
- **No wall-clock bound.** Only fuel limits a call; with `fuel_per_event` up to 1e9 and large
  batches, one batch can hold a blocking thread for minutes. A per-batch deadline via wasmtime epoch
  interruption is future work.
- **`plugin:` tags are not authenticated.** Ingest does not strip an agent-supplied tag starting with
  `plugin:`; YAML rules keyed on plugin tags trust agent input like any other event field.
- **Plugins also run on resent and duplicate events.** The Agent resends a batch until it is
  acknowledged, and ingest evaluates the repeats again, as it does for YAML rules. A detection
  plugin can raise the same alert again with a new alert id, and a duplicate event id inside one
  batch is evaluated twice. This is the same debt as duplicate rule alerts on resend (see
  ROADMAP-REMAINING); the 12a exporters are shielded, storage is not.
- **JSON serialization cost per event.** Each event is serialized once per batch per kind
  (enrichment and detection), then copied into guest memory and parsed by the guest. A binary ABI
  or a field subset would be cheaper.
- **Enrichment plugins do not see each other's tags**, because the input is serialized once per
  `enrich_batch`. Detection plugins and YAML rules see all of them.
- **No signatures and no registry.** The SHA-256 pin proves the file is the one the operator
  configured, not who wrote it.
- **Global, not per tenant.** One plugin set serves every tenant; there is no per-tenant plugin,
  budget or status.
- **No hot reload.** Any change needs a restart.
- **Fuel is not wall-clock time.** There is no wall-clock timeout; a plugin that is cheap in
  instructions but slow in memory access is bounded only by fuel and the memory cap.
- **Leaking guests count against the memory cap.** One instance serves a whole batch, so a guest that
  never frees accumulates memory over the batch and may hit the cap.
- **Counters live in memory** and reset at restart.
- **No console screen**; status is the API and the CLI.

## Alternatives rejected

- **WASI.** Gives modules clocks, randomness and optionally files and sockets. It enlarges the
  attack surface and breaks determinism for no detection use case; no imports is a simpler thing
  to audit.
- **The component model / WIT.** A typed ABI is attractive, but it needs `wit-bindgen` or the
  component toolchain on the guest side and a larger Wasmtime feature set on the host. A JSON ABI
  over core modules is enough at this scale; a component-model ABI is a possible v2 (ABI version 1
  leaves room).
- **Extism.** A ready plugin framework, but it adds a host-function layer, its own memory
  conventions and a dependency that tracks Wasmtime, and its ambient host functions run against the
  "no ambient authority" requirement.
- **Embedded scripting (Lua, Rhai).** Easy to write, but sandboxing and bounding an interpreter
  (memory, CPU, escape hatches in the standard library) is on us and weaker than WebAssembly's
  model, and the language becomes part of the product's compatibility surface.
- **Native dynamic libraries (dylibs).** Run with the server's full authority; no sandbox, no budget,
  a crash takes the server down, and they are per-platform artifacts.
- **Sensor plugins as subprocesses in this phase.** Different problem (Agent wire protocol, seccomp,
  capabilities); it stays a future phase.

## Cost if wrong, and revisit triggers

| Decision | Cost if wrong | Revisit when |
|---|---|---|
| JSON ABI over core modules | Moderate: a new ABI version means a new export contract; the version export exists for this. | Per-event serialization shows up in profiles, or authors ask for typed bindings (component model). |
| Per-batch instance | Low: instantiation from an `InstancePre` is cheap; it is the price of no cross-batch state. | A plugin needs a warm cache; then a deliberate, bounded state API, not shared memory. |
| Fuel, no wall clock | Low: fuel is deterministic and portable. | A plugin is cheap in fuel but slow in practice. |
| Global plugins | Moderate: a tenant-aware plugin set needs per-tenant status and budgets. | A multi-tenant deployment wants tenants to bring their own logic. |
| SHA-256 pin only | Moderate if a registry appears. | Plugins are distributed by someone other than the operator. |
| Reject `:` in YAML rule ids | Low: no bundled rule used it. | Never expected. |
