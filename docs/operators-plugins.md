# Plugins: custom detection and enrichment logic as sandboxed WASM

Phase 12b. The server can run operator-supplied WebAssembly modules on every ingested event. A
**detection** plugin returns alerts; an **enrichment** plugin returns tags that are added to the
event before it is stored. This guide covers the configuration, the plugin ABI, a Rust example, the
per-event budgets, what every failure counter means, the status endpoint and CLI, and the security
model. Design: `docs/superpowers/specs/2026-11-06-phase-12b-wasm-plugins-design.md`. Decision
record: `docs/adr/ADR-013-wasm-plugins.md`. Overhead measurement: `PERFORMANCE.md`,
"Phase 12b - plugin overhead".

Plugins run **inside `osiris-server`** only. The Agent never loads third-party code and does not
link the plugin crate.

## Quick start

1. Build or obtain a `.wasm` file that follows the ABI below.
2. Compute its SHA-256 (lowercase hex): `sha256sum entropy.wasm`.
3. Add a `plugins:` list to the server YAML.

```yaml
plugins:
  - name: entropy
    kind: detection
    path: /etc/osiris/plugins/entropy.wasm
    sha256: 3f5a0c0d9e0b6a7d1c2e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8
```

4. Restart the server. Plugins are read at startup; there is no hot reload.

With no `plugins:` key (or an empty list) the server creates no WebAssembly runtime and ingestion is
unchanged. A bad entry or a module that fails verification stops the server at startup with exit
code 1 and a message that names the plugin.

Check it:

```
osiris plugins status
curl -H "Authorization: Bearer $TOKEN" https://server:8080/api/v1/plugins
```

## Configuration reference

A plugin entry is one flat YAML mapping. Unknown keys are rejected.

| Field | Type | Default | Range / rule | Meaning |
|---|---|---|---|---|
| `name` | string | required | `[a-z0-9_-]{1,64}`, unique | Names the plugin in status, logs, alert ids and tags. |
| `kind` | string | required | `detection` or `enrichment` | What the plugin may return (see "Output"). |
| `path` | path | required | readable file | The module. Used as written, so prefer an absolute path. |
| `sha256` | string | required | 64 lowercase hex characters | Digest of the module file. A mismatch refuses startup. |
| `version` | integer | `1` | `u32` | Becomes `rule_version` of every alert the plugin raises. Bump it when you change the module. |
| `fuel_per_event` | integer | `10000000` | `1..=1000000000` | Instruction budget (fuel) for one event. See "Budgets". |
| `memory_max_mib` | integer | `16` | `1..=256` | Cap on the module's single linear memory, in MiB. A module that declares more than one memory is rejected at load. |
| `enabled` | bool | `true` | | `false` keeps the entry in status but never reads or runs the module. |

Validation of every field (including those of disabled plugins) happens when the server config is
loaded. A disabled plugin's file is not opened, so its `sha256` is not checked and a missing file
does not stop startup. If every configured plugin is disabled, no runtime is created.

## ABI version 1

A plugin is a **core WebAssembly module with no imports**. A module that declares any import is
rejected at load. There is no WASI, no host function, no clock, no randomness and no I/O.

### Exports

| Export | Type | Meaning |
|---|---|---|
| `memory` | memory (32-bit, not shared) | The module's linear memory. |
| `osiris_abi_version` | `() -> i32` | Must return `1`. |
| `osiris_alloc` | `(len: i32) -> i32` | Returns a pointer to `len` writable bytes in `memory`. |
| `osiris_on_event` | `(ptr: i32, len: i32) -> i64` | Reads the input at `ptr..ptr+len`, returns `(out_ptr << 32) \| out_len`. |

A missing export, an export with the wrong type, a 64-bit or shared memory, or an ABI version other
than 1 refuses startup.

### Per-event call sequence

1. The host sets the fuel budget to `fuel_per_event`.
2. It calls `osiris_alloc(len)` for the input size.
3. It copies the input into `memory` at the returned pointer.
4. It calls `osiris_on_event(ptr, len)`.
5. It interprets the returned `i64`:
   - exactly `0`: **no output** (nothing to add; not a failure);
   - anything else: `out_ptr = ret >> 32`, `out_len = ret & 0xFFFFFFFF`. The host bounds-checks
     `out_ptr..out_ptr+out_len` against `memory` and reads those bytes.

**A return of `(ptr, 0)` (a non-zero pointer with length 0) is an output failure, not "no
output".** The empty byte string is not valid JSON. To say "nothing", return exactly `0`.

The fuel budget covers both calls (`osiris_alloc` and `osiris_on_event`).

### Input

UTF-8 JSON of the `CanonicalEvent`, exactly as the YAML rule engine sees it
(`serde_json::to_value(event)`), with `raw_event` removed. Enum fields use their wire spelling, for
example `event_type` is `"PROCESS_EXEC"`. A process event carries `process.exe_path`,
`process.cmdline` and so on; see `crates/osiris-schema/src/envelope.rs` for the full shape.

Two details matter when you combine plugins:

- The input of one batch is serialized **once per `enrich_batch`**. **Enrichment plugins in the
  same batch do not see each other's tags**; the `tags` array an enrichment plugin receives is the
  event's tags as they were before any plugin ran.
- Detection plugins run after enrichment, so they (and the YAML rules) **do** see the enrichment
  tags, in their full `plugin:<name>:<tag>` form.

### Output

A UTF-8 JSON object. Unknown keys are rejected. Both keys are optional.

```json
{ "alerts": [ { "id": "high_entropy_cmdline", "severity": "HIGH",
                "reasons": ["command line entropy 5.9 > 5.0"] } ],
  "tags":   [ "dga_suspect" ] }
```

| Rule | Limit |
|---|---|
| Output size | at most 64 KiB (65 536 bytes) |
| Alerts per call | at most 8 |
| Tags per call | at most 16 |
| Alert `id` | `[a-z0-9_]{1,64}` |
| Alert `severity` | the existing severity wire form (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| Alert `reasons` | 1 to 8 strings, none blank, each at most 512 bytes |
| Tag | `[a-z0-9_:.-]{1,64}` |
| `kind: detection` | may return `alerts`; returning any `tags` is an error |
| `kind: enrichment` | may return `tags`; returning any `alerts` is an error |

Any violation discards the **whole output of that call**; nothing is partially applied. The failure
is counted as an output failure (see "Failure counters").

### What the host does with the output

- **Alert.** `rule_id = "plugin:<plugin name>:<id>"`, `rule_version` = the plugin's `version`,
  `rule_content_hash` = the configured `sha256`, evidence = the event's id, timestamp and host
  taken from the event. The alert is stored and exported exactly like a YAML-rule alert and flows
  through risk, correlation and the 12a exporters.
- **Tag.** Appended to the event's `tags` as `plugin:<plugin name>:<tag>`, skipping duplicates, so
  a plugin-produced tag is distinguishable from a sensor or rule tag (but see the note below). YAML rules can match it.

The `plugin:` prefix is reserved: the YAML rule loader rejects any rule id that contains `:`, so a
YAML rule can never produce an alert id that collides with a plugin's.

The prefix is reserved for alert rule ids only and is not authenticated on tags: ingest does not strip
an agent-supplied tag that starts with `plugin:`, so an agent can send one. A YAML rule keyed on a
plugin tag therefore trusts agent input as much as any other event field.

## A Rust guest example

**Not built by CI.** CI never compiles a guest; the test fixtures are hand-written WAT. This is an
illustration of the ABI, a detection plugin that alerts on a netcat image path.

`Cargo.toml`:

```toml
[package]
name = "nc-hunter"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
serde_json = "1"

[profile.release]
opt-level = "s"
lto = true
panic = "abort"
```

`src/lib.rs` (plain `std`, no `#![no_std]`):

```rust
use std::cell::RefCell;

use serde_json::{json, Value};

thread_local! {
    // The output bytes live here until the next call, so nothing leaks per event.
    static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

#[no_mangle]
pub extern "C" fn osiris_abi_version() -> i32 {
    1
}

/// Hands out `len` bytes by leaking a boxed slice; `osiris_on_event` takes it back.
#[no_mangle]
pub extern "C" fn osiris_alloc(len: i32) -> i32 {
    let buf = vec![0u8; len as usize].into_boxed_slice();
    Box::into_raw(buf) as *mut u8 as usize as i32
}

#[no_mangle]
pub extern "C" fn osiris_on_event(ptr: i32, len: i32) -> i64 {
    // Reclaim (and free at the end of this call) the buffer osiris_alloc leaked.
    let input = unsafe {
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            ptr as usize as *mut u8,
            len as usize,
        ))
    };
    let Ok(event) = serde_json::from_slice::<Value>(&input) else {
        return 0;
    };
    let is_nc = event["process"]["exe_path"]
        .as_str()
        .is_some_and(|p| p == "nc" || p.ends_with("/nc"));
    if !is_nc {
        return 0; // exactly 0 = no output
    }
    let out = json!({ "alerts": [ {
        "id": "netcat_executed",
        "severity": "HIGH",
        "reasons": ["process image is netcat"]
    } ] });
    OUT.with(|o| {
        let mut o = o.borrow_mut();
        *o = serde_json::to_vec(&out).unwrap();
        ((o.as_ptr() as usize as i64) << 32) | o.len() as i64
    })
}
```

Build and install:

```
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
sha256sum target/wasm32-unknown-unknown/release/nc_hunter.wasm
```

The guest above frees its input buffer on every call. A guest that never frees (a bump allocator
or a leaked `Vec`) still works, but note that one instance serves all events of a batch (see
"Isolation"), so leaked bytes accumulate over the batch and count against `memory_max_mib`.

If a toolchain adds an import to the module, load fails with `module declares imports; plugins may
have none`. Inspect the module (`wasm-tools print x.wasm | grep import`) and build with
`panic = "abort"` and without WASI.

## Ordering

For each ingest call (the events of one batch: on the mTLS path, one Agent batch from one host; on the spool-tailer path, whatever one poll returned, which may span several hosts and tenants):

1. Events already owned by a different host are dropped (existing behaviour).
2. **Enrichment plugins**, in config order, each over every kept event. Tags are added to the events.
3. **Storage write** of the events, including the plugin tags.
4. **YAML detection rules**, then **detection plugins** in config order, over every kept event.
   Plugin alerts are appended to the rule alerts; storage, risk, correlation and exporters treat
   them identically.

So YAML rules can match plugin tags, and detection plugins see the stored form of the event.

### Plugins also run on resent and duplicate events

The Agent resends a batch until the server acknowledges it, so ingest sometimes sees events it has
already stored. Plugins run on those events again, like the YAML rules do. A resent event is
re-enriched (its tags are deduplicated, so storing it again does not duplicate tags) and a
detection plugin can raise the same alert again with a new alert id. This is the same existing
debt as duplicate YAML-rule alerts on resend (see `docs/ROADMAP-REMAINING.md`); the 12a exporters
are shielded from it, storage is not. Also, a duplicate event id inside one batch is evaluated
twice. Write plugins that are deterministic and idempotent.

## Isolation: no state across batches

For each ingest call, every plugin gets a **fresh instance** (fresh `Store`, fresh linear memory,
fresh globals) that is reused for the events of that batch and dropped at the end. Nothing survives
to the next batch: a global counter starts again at its initial value. After a trap, a fuel
exhaustion, a memory failure or an output failure inside a batch, that instance is thrown away and
the next event of the batch gets a new one. A plugin therefore cannot keep a cache, a counter or a
window across batches, and it must not rely on state between two events of one batch either (a
failure resets it). If you need cross-event logic, express it as a YAML correlation rule.

## Budgets

| Budget | Value | Enforced by |
|---|---|---|
| Instructions per event | `fuel_per_event`, default 10 000 000, range 1 to 1 000 000 000 | Wasmtime fuel metering, reset before every event; covers `osiris_alloc` and `osiris_on_event`. |
| Linear memory | `memory_max_mib`, default 16, range 1 to 256 | Wasmtime store limits (`memories` = 1). Caps the module's single linear memory; a module declaring more than one memory is rejected at load, and one whose initial memory exceeds the cap refuses startup. |
| Wasm call stack | 512 KiB (not configurable) | Wasmtime. Unbounded recursion traps instead of crashing the host. |
| Instances / tables | 1 instance, 1 table, 10 000 table elements | Wasmtime store limits. |
| Output | 64 KiB, 8 alerts, 16 tags, per call | The host, before anything is applied. |

The budget is enforced by the runtime, not by the plugin's cooperation. A plugin that loops
forever costs at most `fuel_per_event` instructions per event, is counted under `failures_fuel`,
and the event and every other plugin and rule proceed. Fuel is a count of executed instructions,
not wall-clock time; there is no wall-clock timeout. Tune `fuel_per_event` from
`total_fuel_used / calls` in the status output: set it comfortably above the typical use.

## Failure counters

A failed call never fails the event, the batch or ingest. The event proceeds as if the plugin had
returned nothing, the failure is counted under exactly one of these counters, and the plugin gets a
fresh instance for the next event.

| Counter | Counted when |
|---|---|
| `failures_trap` | The guest trapped for any reason other than fuel or memory: `unreachable` (a Rust panic with `panic = "abort"`), integer divide by zero, out-of-bounds access in the guest, call-stack overflow (deep recursion), a missing export on the instance, or a failure to create the instance. |
| `failures_fuel` | The call used its whole `fuel_per_event` budget (typically an infinite or very long loop). |
| `failures_memory` | A `memory.grow` was refused because it would pass `memory_max_mib` (or the module's own maximum), including the trap that follows when the guest cannot handle the refusal, and a bad pointer or length produced while a growth was being denied. |
| `failures_output` | The call returned, but its result is unusable: a pointer or length outside `memory` (including `out_ptr + out_len` overflowing), `osiris_alloc` returning a pointer outside memory, output over 64 KiB, `(ptr, 0)` with a zero length, invalid UTF-8, invalid JSON, a non-object, an unknown key, a schema violation (bad id, bad tag, blank or over-long reason, wrong number of reasons), more than 8 alerts or 16 tags, a detection plugin returning tags, an enrichment plugin returning alerts, or an event too large for the ABI. |

Other counters in the status:

| Field | Meaning |
|---|---|
| `calls` | Events handed to the plugin (one per event per plugin, including failed calls). |
| `alerts` | Alerts applied from successful calls. |
| `tags` | Tags returned by successful calls, counted before de-duplication against tags the event already has. |
| `total_fuel_used` | Fuel consumed over all calls, including failed ones. |
| `last_failure` | `<kind>: <short message>`, for example `fuel: fuel exhausted` or `output: output exceeds 64 KiB`. A fixed description or the Wasmtime trap name; never event or output content. |
| `last_failure_at` | Unix time in nanoseconds of the last failure. |

Counters reset when the server restarts.

### Logging

Each failure updates the counters; the server logs a warning for a plugin **at most once per 60
seconds**, naming the plugin and the failure kind and never event content. At startup the server
logs one `plugin configured` line per entry (name, kind, a 12-character prefix of the digest,
enabled).

## Status endpoint and CLI

`GET /api/v1/plugins` (platform `admin` role only; a tenant-bound admin, an analyst and a viewer
are denied) returns one row per configured plugin, in config order, disabled ones included:

```json
{ "plugins": [ {
  "name": "entropy", "kind": "detection", "enabled": true,
  "sha256": "3f5a0c0d9e0b6a7d1c2e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8",
  "calls": 120000, "alerts": 3, "tags": 0,
  "failures_trap": 0, "failures_fuel": 2, "failures_memory": 0, "failures_output": 0,
  "last_failure": "fuel: fuel exhausted", "last_failure_at": 1762300801123456789,
  "total_fuel_used": 913452211
} ] }
```

With no plugins configured the body is `{"plugins": []}`.

`osiris plugins status` prints a tab-separated table:

```
NAME   KIND       CALLS   ALERTS  TAGS  FAILURES  LAST_FAILURE
```

`FAILURES` is the sum of the four failure counters. **The table has no `ENABLED` column and does
not mark disabled plugins: a disabled plugin appears with all-zero counters, the same as a plugin
that has not seen traffic yet.** Use `--json` to see `enabled` (and the per-kind failure counters,
the digest and the fuel). `--json` prints the API body. The command uses the cached login token (or
`OSIRIS_TOKEN`) and `--server`.

## Troubleshooting

- **Server exits at startup with `invalid plugin configuration: plugin <name>: ...`.** The message
  names the plugin and the problem: `sha256 does not match the module file` (rebuilt the module
  but not the config), `cannot read <path>`, `not a valid WebAssembly module`, `module declares
  imports; plugins may have none`, `missing export \`osiris_alloc\``, `export \`...\` has the wrong
  type`, `unsupported abi version N (expected 1)`, `module failed to instantiate` (for example its
  initial memory is larger than `memory_max_mib`), `duplicate plugin name`, or a range error on
  `fuel_per_event` or `memory_max_mib`. A YAML typo (unknown key) is rejected too.
- **`calls` stays at 0.** The plugin is `enabled: false` (check with `--json`), or no event has
  been ingested since the restart, or the plugin was added to a server that has not been
  restarted.
- **`failures_fuel` rising.** The module is using the whole budget on some events. Compare
  `total_fuel_used / calls` with `fuel_per_event`; raise the budget (up to 1 000 000 000) if the
  work is legitimate, or fix the loop. Remember that 10 000 000 instructions per event over a
  high event rate is real CPU on the ingest thread.
- **`failures_memory` rising.** The guest grows memory past `memory_max_mib`. Raise the cap (up to
  256), or stop leaking: one instance serves a whole batch, so memory that is not freed per event
  accumulates over the batch.
- **`failures_trap` rising.** Read `last_failure` (`unreachable`, `integer divide by zero`, `call
  stack exhausted`, ...). With Rust, `panic = "abort"` turns every panic into `unreachable`.
- **`failures_output` rising.** The plugin returns something that does not match the output
  schema. Check for: returning `(ptr, 0)` instead of `0` for "no output", a tag with an uppercase
  letter or a space, an alert id with `-`, more than 8 alerts or 16 tags, a blank reason, tags from
  a detection plugin or alerts from an enrichment plugin. `last_failure` names the rule broken.
- **A plugin alert or tag appears twice.** The event was resent (see "Plugins also run on resent
  and duplicate events"). Tags are de-duplicated on an event; alerts are not.
- **My enrichment plugin does not see another plugin's tag.** By design: enrichment plugins of one
  batch read the same pre-plugin input. A detection plugin or a YAML rule can read the combined tags.
- **A YAML rule never fires on a plugin tag.** Match the full tag, `plugin:<name>:<tag>`.
- **My YAML rule is rejected after upgrading.** Rule ids may no longer contain `:` (reserved for
  plugin alert ids).

## Security model

- **No ambient authority.** The module may import nothing, so it has no file, network, clock,
  environment, randomness or host-memory access. It is handed one serialized event per call and has no
  channel to the database or to any data outside the batch. One instance and one linear memory serve
  every event of a batch (see "Isolation"), so a plugin can retain earlier events of the batch and
  emit them in a later event's alert reasons or tags. On the spool-tailer path a batch can span
  tenants, so treat a plugin as trusted with every event in the batch. Plugins are operator-installed,
  SHA-256-pinned code; per-tenant batch splitting is future work.
- **Integrity pin.** Every plugin is pinned by the SHA-256 of its file in the server config. A
  changed file refuses startup. The pin protects against a swapped file, not against a malicious
  module you pinned on purpose: review what you deploy. There are no signatures and no plugin
  registry in 12b.
- **Bounded cost.** Fuel, memory, stack, table and output limits are enforced by the runtime.
  Plugin output is untrusted and fully validated before anything is stored; a violation discards the
  whole output.
- **No hot reload.** Plugins load at startup only. To change a plugin, replace the file, update
  `sha256` (and `version`) and restart.
- **Global, not per tenant.** A plugin sees the events of every tenant, like the YAML rules, and its
  alerts are attributed to the event's host. Only deploy plugins you would let read all tenants'
  events. Restrict write access to the plugin directory and the server config accordingly.
- **No content in logs or status.** Failure messages, warnings and the status endpoint carry only
  the plugin name, the failure kind and a fixed description.
- **Supply chain.** The runtime is Wasmtime (core modules only, no WASI, no component model),
  pinned in the workspace; keeping it patched is part of keeping the server patched.
