# Phase 4b: Systemd Sensor + Persistence Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the second half of ARCHITECTURE.md §89's Phase 4 roadmap line — a Systemd Sensor (unit start/stop) and a Persistence Monitor (unit-file and other persistence-checkpoint lifecycle) — completing the identity→process→privilege→persistence chain Phase 4a began, and fixing one real bug Phase 4a's final review parked for this phase.

**Architecture:** Two new sensor crates. `osiris-sensors-systemd` is audit-log-tailing, exactly like Phase 4a's Identity sensor (real, documented `SERVICE_START`/`SERVICE_STOP` auditd records systemd itself emits). `osiris-sensors-persistence` is a new backend shape for this codebase — periodic scan-and-diff over a config-declared list of watched checkpoint paths (systemd unit directories, cron files/dirs, shell profile dirs, `ld.so.preload`, `sudoers.d`), modeled on Phase 3's `NetworkPoller` polling-sensor shape rather than a line tailer. Both feed the existing Normalize → Enrich → Validate → Prioritize pipeline unchanged in shape; only two new `normalize_*` functions and zero new `enrich` relation edges are added (see Global Constraint #6). A real bug in `enrich.rs`, parked by Phase 4a's final review, is fixed first (Task 1) because the Systemd sensor's own session-observation feature depends on it working correctly.

**Tech Stack:** Rust workspace, `tokio`/`async-trait` sensors, `rusqlite` storage, `axum` API, `serde`/`serde_yaml` config, `sha2` for content hashing (already a workspace dependency via `osiris-detect`).

**Spec:** `ARCHITECTURE.md` (project root) — primarily §4.3 (sensor catalog), §9.2-9.4 (envelope/taxonomy/relationships), §26 (worked trace), §89/Phase 4 roadmap line. Also this plan's own Global Constraints below, which record every place this plan's design deviates from or extends the spec's prose with a ruling.

## Global Constraints — scope decisions made for this plan (read before dispatching any task)

1. **Two separate sensor crates, matching §4.3's two separate catalog rows** (unlike Phase 4a, where Identity subsumed Privilege because both come from ONE audit stream). Systemd's runtime lifecycle (`SERVICE_START`/`SERVICE_STOP`) is audit-log-backed — real, standard `type=SERVICE_START`/`type=SERVICE_STOP` auditd records systemd itself emits via `audit_log_user_comm_message` when audit is enabled, carrying the same outer `pid=`/`uid=`/`auid=`/`ses=` + nested `msg='unit=... comm="systemd" exe="..." hostname=? addr=? terminal=? res=...'` shape Phase 4a's `USER_*` records already use. Unit-*file* lifecycle (`.service`/`.timer` files being created/changed/removed) and every other persistence-checkpoint path have no audit-log equivalent available without kernel-level fanotify (deferred to real-Linux validation, matching every other phase's fallback-first ruling) — a periodic scan-and-diff is this plan's chosen backend for **both** unit-file lifecycle and generic persistence paths, because a file appearing/changing/disappearing on disk is exactly that mechanism's native signal. **Ruling: the Persistence Monitor crate owns unit-file lifecycle too** (`SERVICE_CREATE`/`SERVICE_MODIFY`/`SERVICE_DELETE`, `TIMER_CREATE`/`TIMER_MODIFY`) — building a second, separate path-scanner inside the Systemd sensor (which otherwise only has an audit-log tailer, no filesystem-scan capability) would duplicate the whole scan-and-diff engine for no gain. Category/event_type assignment is a lookup from the *watch target's declared kind* (Global Constraint #4), resolved once during Normalize, never guessed from the path string itself.

2. **The `enrich.rs` session observed-vs-inferred precedence bug, parked by Phase 4a's final whole-branch review, is fixed in Task 1, before any Systemd/Persistence code lands.** The bug: `attach_session`'s non-Identity branch unconditionally overwrote an already-*observed* `event.session` (populated directly from a record's own `ses=` field in Normalize — `normalize_privilege_event` already does this) with the pid/ppid-*inferred* session from `SessionResolver::attach`, on any pid whose ancestry resolves to a different (stale or wrong) session. This phase's Systemd sensor populates `session` the same directly-observed way `normalize_privilege_event` does (its own `ses=`), so shipping Systemd events on top of the unfixed bug would launch a second feature on a foundation already known to be broken. Fix: observation wins over inference when both exist; `SessionResolver.attach()` is still called for its pid-inheritance teaching side effect on unrelated descendants, but its return value is only used as a fallback when the event itself carries no session. See Task 1 for the exact diff.

3. **No new `Relation`/`EntityRef` variants, and no new entity-graph edges for Systemd or Persistence events this phase.** A `Systemd::ServiceStart`/`Stop` event's outer `pid=` is genuinely `1` (systemd's own pid) on a real host — there is no attacker-controlled process to graph an edge from, and inventing one would violate the "never fake identity" discipline every earlier phase applied. A Persistence-category event from the periodic scanner carries no pid at all (it wasn't triggered by a process event) — same reasoning. What *is* real and valuable: both `normalize_systemd_event` (this phase) and `normalize_privilege_event` (Phase 4a) populate `session` directly from an observed `ses=`, and — because `QueryPlan.session_id`/`GET /api/v1/identity/story?session_id=…` (Phase 4a, Task 4/7) are category-agnostic — a Systemd event whose `ses=` matches an open SSH session is already surfaced by the *existing* Identity Story endpoint with zero new code, once Task 1's fix lands. This is the phase's actual "identity→…→persistence chain" payoff, and it costs nothing new to wire.

4. **Persistence Monitor's watch targets are explicitly typed in config, never guessed from a path pattern.** `AgentConfig.persistence_watch_paths: Vec<PersistenceWatchTarget>`, each `{ path: String, kind: PersistenceCheckpointKind }` (`kind` one of `systemd_unit_dir`, `cron`, `shell_profile`, `ld_preload`, `sudoers`). An operator who points `kind: cron` at `/etc/systemd/system` by mistake gets exactly what they configured — this plan does not add path-pattern heuristics to second-guess it. The one exception: within a `systemd_unit_dir` target, the sensor distinguishes a discovered `*.service` file from a `*.timer` file by extension (both live in the same directory on a real host) — this is a per-*file* refinement of an already-explicit per-*directory* declaration, not a guess about what the directory itself is for. A `systemd_unit_dir` file with neither extension (`.socket`, `.mount`, `.path`, etc.) is silently skipped — out of scope this phase, the same "documented, deliberate drop, not a silent guess" discipline Phase 4a applied to `setresuid`/`setresgid`.

5. **`EventType::TimerModify` also covers timer-file *removal*** — the frozen taxonomy (`osiris-schema`, Phase 0) has `TIMER_CREATE`/`TIMER_MODIFY` but no `TIMER_DELETE` (§9.3, verified against the live `EventType` enum before writing this plan). Per the established "solve it in the consuming crate, never widen a frozen schema type for one call site" ruling (Phase 1/2/3 precedent), a removed `.timer` file normalizes to `TimerModify` with `event_data.operation: "removed"` disclosing the exact distinction verbatim for any consumer that needs it — never invented as a new enum variant, never silently conflated with an actual modification without the disclosure.

6. **`osiris-schema` is not modified this phase** (Phase 2's Global Constraint #7, reaffirmed every phase since). Verified before writing this plan: `Category::Systemd`/`Category::Persistence` and all seven `EventType` variants this phase needs (`ServiceCreate`, `ServiceModify`, `ServiceStart`, `ServiceStop`, `ServiceDelete`, `TimerCreate`, `TimerModify`, `PersistenceCreated`, `PersistenceModified`, `PersistenceRemoved`) already exist in `crates/osiris-schema/src/event_type.rs`, correctly mapped to their categories in `EventType::category()` — Phase 0 anticipated all of it. `ServiceRef { unit_name, unit_type, action }` (`crates/osiris-schema/src/entities.rs`) and `FileRef` (reused for Persistence-category events' `path`/`hash`) already exist too. Zero schema changes are needed or permitted.

7. **The shared nested-`msg=` audit-record splitter (`RecordParts`/`split_record`, plus the small sentinel helpers `parse_id`/`usable_session`/`unknown_to_none`/`UNSET_ID`) moves from `osiris-sensors-identity` into `osiris-fileutil` in Task 2, before the Systemd sensor is written.** This machinery was written once for Identity/Privilege's `USER_*` records (Phase 4a) and already had one real embedded-quote security fix land in it (Phase 4a's final review). Systemd's `SERVICE_START`/`SERVICE_STOP` records need the *exact same* outer/inner nested-quote split — writing a second copy in a new crate would either duplicate a fix that already had one real bug, or (worse) silently regress it. This is the "third/second copy is one too many" lesson from Phase 1's `osiris-fileutil` extraction, applied one copy earlier than last time on purpose: catching the duplication at 2 is why Phase 4a's own bugfix is worth sharing forward at all. `decode_untrusted_string`/`decode_hex` (hex-decoding of untrusted `cmd=`/`name=` values) is **not** touched or shared — that duplication was explicitly re-ruled justified in Phase 4a (sensor-independence, §4.2) and remains so; only the record-splitting layer moves.

8. **Persistence Monitor's first scan seeds a baseline silently — it never emits `PERSISTENCE_CREATED`/`SERVICE_CREATE` for the pre-existing population found on Agent startup.** This is a deliberate, disclosed *deviation* from Phase 3's `NetworkPoller` precedent (which treats every already-ESTABLISHED connection on its first poll as "new"). The reasoning does not carry over: the population of pre-existing, legitimate cron entries/systemd units/shell-profile lines on any real running system is large and constant, while the population of open TCP connections at a single instant is comparatively small and already transient-tolerant. Treating "everything found on the first scan" as newly-created would flood the shipped detection rule (Task 9) with a false-positive storm on every single Agent (re)start, defeating the rule's purpose. A genuine new/changed/removed artifact appearing between tick N and tick N+1, once the first scan has completed, is still detected correctly — this only silences the very first tick after each Agent start, a narrower and more honestly-scoped limitation window than `LineTailer`'s own precedent.

9. **No `osiris-detect` source changes** (Phase 4a's Global Constraint #13, reaffirmed): the one new rule this phase ships is a config-only YAML file. `eval::field_value`'s dotted-path resolution, `engine::evaluate_rule`'s missing-or-null-is-non-match semantics, and `DetectionEngine::load_from_dir`'s glob-and-sort loading already handle everything the new rule needs — Task 9 verifies this against the live code before writing the rule, exactly as Phase 4a's Task 6 did.

10. **No `osiris-server` changes and no `osiris-cli` verb** (Phase 4a's Global Constraint #14 precedent) for the new `GET /api/v1/systemd/story` endpoint. CLI verbs for systemd/persistence are a Console/CLI-maturity concern for a later phase, matching every prior phase's identical decision for its own new Story endpoint.

11. **The existing `GET /api/v1/files/story?path=…` endpoint (Phase 2) already, for free, serves the persistence-artifact history for any watched path**, because Persistence-category events populate `file.path`/`file.hash` via the same `FileRef` a `files/story` query already filters on. This plan does not build a parallel, redundant "persistence story" endpoint for that half of the taxonomy — only `GET /api/v1/systemd/story?unit_name=…` (Task 10) is new, covering the half of the taxonomy (`ServiceRef.unit_name`-keyed) that `files/story` cannot reach (a `SERVICE_START` event has no `file` at all).

12. **`osiris-storage`/`osiris-storage-sqlite` gain exactly one new `QueryPlan` filter, `unit_name: Option<String>`,** via the identical guarded additive-migration pattern every prior phase established (nullable column, `column_exists`-guarded `ALTER TABLE`, one new index). No `Storage` trait change.

## Task 1: Fix `enrich.rs`'s session precedence bug + `SessionResolver.members` dedup

**Files:**
- Modify: `crates/osiris-pipeline/src/enrich.rs`
- Modify: `crates/osiris-pipeline/src/session_resolver.rs`

**Interfaces:**
- Consumes: nothing new — this is a correctness fix to existing Phase 4a code.
- Produces: `attach_session`'s corrected precedence (observation over inference), unchanged public signature. `SessionResolver.members: HashMap<String, Vec<u32>>` becomes `HashMap<String, HashSet<u32>>` — `record_login`'s and `attach`'s callers are unaffected (neither is public API outside this crate; `Pipeline`/`enrich` are the only callers and neither reads `members` directly).

**Before writing any code**, re-read `crates/osiris-pipeline/src/enrich.rs`'s current `attach_session` function and `crates/osiris-pipeline/src/session_resolver.rs`'s `SessionResolver` in full — both already exist from Phase 4a and this task only changes them, it does not rewrite them.

- [ ] **Step 1: Write the failing regression test for the precedence bug**

Append to `crates/osiris-pipeline/src/enrich.rs`'s `#[cfg(test)] mod tests`:

```rust
    /// Regression test for the Phase 4a final-review finding parked for
    /// this phase: an event that already carries an OBSERVED session
    /// (populated directly from the record's own `ses=` in Normalize, the
    /// same way `normalize_privilege_event` already works) must keep that
    /// session even when the pid/ppid chain would infer a *different* one —
    /// the nested-login (`su`) case where a pid moves from one real audit
    /// session into another.
    #[test]
    fn an_observed_session_wins_over_a_pid_inferred_one() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();

        // pid 100 is the root of session "3" (e.g. the original SSH login).
        let _login_a = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        // pid 200 execs under 100 and inherits session "3" by ppid chain.
        let _bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);

        // A second, independent login roots session "5" at pid 500 (e.g. a
        // concurrent console session, unrelated to pid 200's ancestry).
        let mut login_b = login_event(host_id, 500);
        login_b.session.as_mut().unwrap().session_id = "5".to_string();
        login_b.session.as_mut().unwrap().remote_addr = None;
        login_b.session.as_mut().unwrap().auth_method = Some("login".to_string());
        let _login_b = enrich(login_b, "boot-1", &mut resolver, &mut sessions);

        // pid 200 (a known member of session "3" via inheritance) now
        // produces an event whose record OWN `ses=` says "5" — e.g. it ran
        // `su` and its next audit-visible action is a Systemd/Privilege
        // record carrying the real, current, observed session. Normalize
        // would have populated `event.session` from that observation before
        // `enrich` ever runs; this test constructs that pre-enriched shape
        // directly, exactly as `normalize_privilege_event` and (this
        // phase's) `normalize_systemd_event` do.
        let mut observed_event = bare_event(host_id, 200, 100);
        observed_event.session = Some(SessionRef {
            session_id: "5".to_string(),
            tty: None,
            remote_addr: None,
            auth_method: None,
        });
        let result = enrich(observed_event, "boot-1", &mut resolver, &mut sessions);

        assert_eq!(
            result.session.as_ref().unwrap().session_id,
            "5",
            "the record's own observed session must win over the pid-inferred one"
        );
        assert_eq!(
            result.session.as_ref().unwrap().auth_method.as_deref(),
            Some("login"),
            "the observed session id must still be enriched from its own known record"
        );
    }

    /// When the observed session id does not (yet, or ever) match a known
    /// login record, the minimal observed ref must be kept exactly as
    /// Normalize produced it — not cleared, and not replaced by an
    /// unrelated pid-inferred session.
    #[test]
    fn an_observed_session_with_no_known_record_is_kept_minimal_not_overwritten() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();

        let _login = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        let _bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);

        // pid 200 is a known member of session "3", but this event's own
        // record observed a session ("9") the resolver has never heard of
        // (its login happened before the Agent started).
        let mut observed_event = bare_event(host_id, 200, 100);
        observed_event.session = Some(SessionRef {
            session_id: "9".to_string(),
            tty: None,
            remote_addr: None,
            auth_method: None,
        });
        let result = enrich(observed_event, "boot-1", &mut resolver, &mut sessions);

        assert_eq!(
            result.session.as_ref().unwrap().session_id,
            "9",
            "an unknown observed session must be kept, never silently swapped for pid-3"
        );
        assert!(result.session.as_ref().unwrap().tty.is_none());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p osiris-pipeline an_observed_session`
Expected: `an_observed_session_wins_over_a_pid_inferred_one` FAILS — `result.session.as_ref().unwrap().session_id` is `"3"`, not `"5"` (today's bug: the pid-inferred session silently wins). `an_observed_session_with_no_known_record_is_kept_minimal_not_overwritten` FAILS too — today's `attach_session` returns early (via `sessions.record_for(&session_id)?` failing on the *inferred* `"3"`... actually verify: with today's code, `sessions.attach(200, 100)` returns `Some("3")` since pid 200 is already `by_pid`-mapped; `record_for("3")` succeeds, so `event.session` gets overwritten to the *full* session "3" record, wiping out the observed `"9"` entirely). Confirm the actual failure message matches this reasoning before moving on — this is the precise bug shape Global Constraint #2 describes.

- [ ] **Step 3: Fix `attach_session`**

In `crates/osiris-pipeline/src/enrich.rs`, replace the non-Identity branch of `attach_session` (everything after the `if event.category == Category::Identity { ...; return; }` block):

```rust
    let Some(pid) = event.process.as_ref().map(|p| p.pid) else {
        return;
    };
    let ppid = current_ppid(event);
    let inferred_session_id = sessions.attach(pid, ppid);

    // An event may already carry an observed session id, populated
    // directly from the record's own `ses=` field in Normalize
    // (`normalize_privilege_event` does this today; this phase's
    // `normalize_systemd_event` will too). Observation always wins over
    // pid/ppid inference here — the same "never let a guess override a
    // fact" discipline this stage already applies to process identity
    // (`PROCESS_KEY_PROVISIONAL`) and file identity (no edge over a
    // fabricated one). `sessions.attach` above is still called
    // unconditionally for its pid-inheritance teaching side effect —
    // unrelated descendants of `pid` must still resolve correctly through
    // it — only its *return value* is demoted to a fallback here.
    let session_id = match event.session.as_ref() {
        Some(observed) => observed.session_id.clone(),
        None => match inferred_session_id {
            Some(inferred) => inferred,
            None => return,
        },
    };

    let Some(record) = sessions.record_for(&session_id) else {
        // The session id (observed or inferred) doesn't match a known
        // login record. Leave `event.session` exactly as Normalize
        // produced it — a minimal ref, or `None` — rather than discarding
        // real, directly-observed data because enrichment has nothing
        // fuller to offer it.
        return;
    };
    event.session = Some(SessionRef {
        session_id: record.session_id.clone(),
        tty: record.tty.clone(),
        remote_addr: record.remote_addr.clone(),
        auth_method: record.auth_method.clone(),
    });
```

Run: `cargo test -p osiris-pipeline`
Expected: PASS — both new tests, and every pre-existing `enrich.rs` test (`a_process_execed_inside_a_session_inherits_that_session`, `a_real_uid_escalation_gains_an_executed_as_edge_to_the_target_user`, etc.) still green. None of them exercise an event with a *pre-populated, differing* `event.session`, so the fix is additive from their perspective.

- [ ] **Step 4: Deduplicate `SessionResolver.members`**

In `crates/osiris-pipeline/src/session_resolver.rs`, change the `members` field and its two call sites:

```rust
use std::collections::{HashMap, HashSet};
```

```rust
    members: HashMap<String, HashSet<u32>>,
```

In `record_login`, change `self.members.entry(session_id).or_default().push(pid);` to:

```rust
        self.members.entry(session_id).or_default().insert(pid);
```

In `attach`, change `self.members.entry(session_id.clone()).or_default().push(pid);` to:

```rust
            self.members
                .entry(session_id.clone())
                .or_default()
                .insert(pid);
```

In `forget`, `for pid in pids` still works unchanged (`HashSet<u32>` is `IntoIterator<Item = u32>` exactly like `Vec<u32>`).

- [ ] **Step 5: Add the regression test for the duplicate-pid cleanup**

Append to `crates/osiris-pipeline/src/session_resolver.rs`'s `#[cfg(test)] mod tests`:

```rust
    /// A real audit stream emits both `USER_LOGIN` and `USER_START` for one
    /// session, and `enrich.rs`'s `attach_session` calls `record_login` for
    /// both — `members` must not accumulate the same pid twice from that,
    /// or `forget`'s iteration does needless repeated work per session.
    #[test]
    fn record_login_called_twice_for_the_same_pid_does_not_duplicate_membership() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        sessions.record_login(100, ssh_session());
        sessions.forget("3");
        // If pid 100 had been double-counted, this would still resolve
        // (the first `forget` pass would only remove one of two identical
        // entries) — asserting `None` here is the actual proof.
        assert_eq!(sessions.attach(100, 1), None);
    }
```

- [ ] **Step 6: Run the full pipeline test suite**

Run: `cargo test -p osiris-pipeline`
Expected: PASS — all tests green, including the new ones from Steps 1 and 5.

- [ ] **Step 7: Commit**

```bash
git add crates/osiris-pipeline/src/enrich.rs crates/osiris-pipeline/src/session_resolver.rs
git commit -m "fix(pipeline): observed session wins over pid-inferred one in attach_session"
```

## Task 2: Extract the shared nested-`msg=` audit-record splitter into `osiris-fileutil`

**Files:**
- Create: `crates/osiris-fileutil/src/nested_msg_record.rs`
- Modify: `crates/osiris-fileutil/src/lib.rs`
- Modify: `crates/osiris-sensors/identity/src/audit_record.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `osiris_fileutil::{RecordParts, split_record, parse_id, usable_session, unknown_to_none}`, all re-exported from the crate root. Task 5's Systemd sensor consumes these directly.
- **No behavior change** in `osiris-sensors-identity` — every one of its existing tests (20 parser tests, 3 sensor tests) must still pass unchanged after this refactor.

**Before writing any code**, open `crates/osiris-sensors/identity/src/audit_record.rs` and confirm the exact current text of `RecordParts`, `split_record`, `parse_id`, `usable_session`, `unknown_to_none`, and `UNSET_ID` — this task moves them verbatim (same doc comments, same logic), it does not rewrite them. Confirm `basename` and `decode_untrusted_string`/`decode_hex` are **not** in this list — Global Constraint #7 explicitly excludes them from the move.

- [ ] **Step 1: Write the failing test in the new shared module's location**

Create `crates/osiris-fileutil/src/nested_msg_record.rs` with a `#[cfg(test)] mod tests` containing exactly the identity crate's own existing `split_record`/sentinel-handling tests, copied verbatim (do not invent new ones — this step is a relocation, and a diff that's "the same tests in a new file" is how the reviewer verifies nothing changed). At minimum, copy every test in the identity crate's `audit_record.rs` whose name contains `split_record`, `usable_session`, `parse_id`, or `unknown_to_none` — grep for them first to get the exact list, then paste each one unchanged except updating any `use super::*;` paths to match the new file's items.

- [ ] **Step 2: Run the new tests to verify they fail to compile**

Run: `cargo test -p osiris-fileutil`
Expected: FAIL to compile — `RecordParts`/`split_record`/etc. don't exist yet in this crate.

- [ ] **Step 3: Move the implementation**

In `crates/osiris-fileutil/src/nested_msg_record.rs`, above the test module, paste the following items **exactly as they exist today** in `crates/osiris-sensors/identity/src/audit_record.rs` (their current doc comments already describe the design correctly and need no changes — Phase 4a's GC#9 language they cite is retained verbatim as historical record of *why* this exists):

- `const UNSET_ID: &str = "4294967295";` (add `pub` — becomes `pub const UNSET_ID`)
- `pub struct RecordParts { ... }` and its `impl RecordParts { pub fn get(...) }`
- `pub fn split_record(line: &str) -> Option<RecordParts> { ... }`
- `pub fn parse_id(value: Option<&str>) -> Option<u32> { ... }` (add `pub`)
- `pub fn usable_session(value: Option<&str>) -> Option<String> { ... }` (add `pub`)
- `pub fn unknown_to_none(value: Option<&str>) -> Option<&str> { ... }` (add `pub`)

Add the necessary `use` line at the top of the new file:

```rust
use std::collections::HashMap;

use crate::{parse_audit_msg_id, tokenize, AuditMsgId};
```

- [ ] **Step 4: Export from the crate root**

In `crates/osiris-fileutil/src/lib.rs`, add:

```rust
pub mod nested_msg_record;

pub use nested_msg_record::{
    parse_id, unknown_to_none, usable_session, RecordParts, UNSET_ID,
};
pub use nested_msg_record::split_record;
```

Run: `cargo test -p osiris-fileutil`
Expected: PASS — the relocated tests pass in their new home.

- [ ] **Step 5: Delete the moved items from the identity crate and import them instead**

In `crates/osiris-sensors/identity/src/audit_record.rs`:
- Delete the `UNSET_ID` const, the `RecordParts` struct + impl, `split_record`, `parse_id`, `usable_session`, `unknown_to_none` — all now live in `osiris-fileutil`.
- Delete the test functions you copied in Step 1 from this file's own `#[cfg(test)] mod tests` (they now live in `osiris-fileutil`, not duplicated here).
- Change the top-of-file `use` block from:

```rust
use osiris_fileutil::{parse_audit_msg_id, tokenize, AuditMsgId};
```

to:

```rust
use osiris_fileutil::{
    parse_id, split_record, unknown_to_none, usable_session, RecordParts,
};
```

(Drop `parse_audit_msg_id`/`tokenize`/`AuditMsgId` from this crate's direct imports — they're now only used inside `split_record`, which lives in `osiris-fileutil`.)

- [ ] **Step 6: Run the identity crate's full test suite**

Run: `cargo test -p osiris-sensors-identity`
Expected: PASS — every test that existed before this task still passes, using the imported shared functions. Count the tests before and after this task (should be the moved-out count fewer, e.g. if 8 tests moved, this crate now has 20 total instead of 28, with those 8 now living in and counted by `osiris-fileutil`'s own test run).

- [ ] **Step 7: Run the full workspace build**

Run: `cargo build --workspace --all-targets`
Expected: PASS — confirms no other crate broke from the re-export changes (`osiris-fileutil` is a leaf crate per `check_no_internal_deps osiris-fileutil` in `tools/check-dep-graph.sh`, so only `osiris-sensors-identity` and `osiris-sensors-fs` depend on it; `osiris-sensors-fs` does not use any of the moved items and must be unaffected).

- [ ] **Step 8: Commit**

```bash
git add crates/osiris-fileutil/src/lib.rs crates/osiris-fileutil/src/nested_msg_record.rs crates/osiris-sensors/identity/src/audit_record.rs
git commit -m "refactor(fileutil): share the nested-msg audit-record splitter with future audit-based sensors"
```

## Task 3: `osiris-sensor-api` — `RawEvent::Systemd`/`RawEvent::Persistence`

**Files:**
- Modify: `crates/osiris-sensor-api/src/lib.rs`
- Modify: `crates/osiris-sensor-api/src/raw_event.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `SystemdOperation`, `SystemdEventRaw`, `PersistenceOperation`, `PersistenceCheckpointKind`, `PersistenceEventRaw`, `RawEvent::Systemd`, `RawEvent::Persistence`, all re-exported from the crate root. Task 4's normalize functions and Tasks 5/6's sensors consume these exact field lists verbatim.

- [ ] **Step 1: Write the failing tests**

Append to `crates/osiris-sensor-api/src/raw_event.rs`'s `#[cfg(test)] mod tests`:

```rust
    fn systemd_raw() -> SystemdEventRaw {
        SystemdEventRaw {
            operation: SystemdOperation::Start,
            unit_name: "sshd.service".to_string(),
            pid: 1,
            uid: 0,
            auid: Some(1000),
            session_id: Some("3".to_string()),
            success: true,
            exe_path: "/usr/lib/systemd/systemd".to_string(),
            comm: "systemd".to_string(),
            timestamp_ns: 1_690_000_000_123_000_000,
            audit_serial: Some(501),
            source: RawEventSource::Audit,
        }
    }

    #[test]
    fn systemd_raw_event_round_trips_through_raw_event() {
        let raw = RawEvent::Systemd(systemd_raw());
        assert_eq!(raw.timestamp_ns(), 1_690_000_000_123_000_000);
        match raw {
            RawEvent::Systemd(s) => {
                assert_eq!(s.operation, SystemdOperation::Start);
                assert_eq!(s.unit_name, "sshd.service");
                assert_eq!(s.session_id.as_deref(), Some("3"));
            }
            other => panic!("expected RawEvent::Systemd, got {other:?}"),
        }
    }

    fn persistence_raw() -> PersistenceEventRaw {
        PersistenceEventRaw {
            operation: PersistenceOperation::Created,
            checkpoint_kind: PersistenceCheckpointKind::SystemdUnit,
            path: "/etc/systemd/system/backdoor.service".to_string(),
            content_hash: Some("a".repeat(64)),
            size: Some(128),
            timestamp_ns: 1_690_000_010_000_000_000,
            source: RawEventSource::Procfs,
        }
    }

    #[test]
    fn persistence_raw_event_round_trips_through_raw_event() {
        let raw = RawEvent::Persistence(persistence_raw());
        assert_eq!(raw.timestamp_ns(), 1_690_000_010_000_000_000);
        match raw {
            RawEvent::Persistence(p) => {
                assert_eq!(p.operation, PersistenceOperation::Created);
                assert_eq!(p.checkpoint_kind, PersistenceCheckpointKind::SystemdUnit);
                assert_eq!(p.path, "/etc/systemd/system/backdoor.service");
                assert_eq!(p.content_hash.as_deref(), Some("a".repeat(64).as_str()));
            }
            other => panic!("expected RawEvent::Persistence, got {other:?}"),
        }
    }

    /// A removed artifact carries no content hash — there is nothing left
    /// to hash, and inventing one (e.g. reusing the last-known hash) would
    /// misrepresent a deletion as a content fact.
    #[test]
    fn a_removed_persistence_event_carries_no_content_hash() {
        let mut raw = persistence_raw();
        raw.operation = PersistenceOperation::Removed;
        raw.content_hash = None;
        raw.size = None;
        let event = RawEvent::Persistence(raw);
        match event {
            RawEvent::Persistence(p) => {
                assert!(p.content_hash.is_none());
                assert!(p.size.is_none());
            }
            other => panic!("expected RawEvent::Persistence, got {other:?}"),
        }
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p osiris-sensor-api`
Expected: FAIL to compile — `cannot find type SystemdEventRaw`, `cannot find function/variant RawEvent::Systemd`.

- [ ] **Step 3: Add the two raw shapes**

In `crates/osiris-sensor-api/src/raw_event.rs`, after the existing `PrivilegeEventRaw` struct and before the `RawEvent` enum definition, add:

```rust
/// The two systemd unit-lifecycle operations this phase's audit-backed
/// sensor observes (plan Global Constraint #1). Each maps 1:1 onto one
/// standard auditd record type systemd itself emits when audit is enabled:
/// `Start` <- `type=SERVICE_START`, `Stop` <- `type=SERVICE_STOP`. Unlike
/// Identity/Privilege's records, the outer `pid=`/`uid=` are genuinely
/// systemd's own (typically `pid=1 uid=0`), not an attacker-controlled
/// process — there is no process identity to correlate here, only session
/// identity when the record's own `ses=` reports one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemdOperation {
    Start,
    Stop,
}

/// A systemd unit start/stop record, parsed from one auditd `SERVICE_START`/
/// `SERVICE_STOP` line. Same nested `outer key=value` + single-quoted
/// `msg='...'` shape as Identity/Privilege's `USER_*` records (plan Global
/// Constraint #7) — `crate::osiris_fileutil::split_record` (shared, not
/// reimplemented) handles both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdEventRaw {
    pub operation: SystemdOperation,
    /// From the nested `msg='unit=...'`, full unit name including its
    /// `.service`/`.timer` suffix.
    pub unit_name: String,
    /// The outer `pid=` — genuinely systemd's own pid (typically `1`) on a
    /// real host, not an actor's process. Kept rather than discarded: it is
    /// what the record actually reports, and Normalize/Enrich treat it
    /// exactly like any other honestly-reported-but-uninteresting pid
    /// (`PROCESS_KEY_PROVISIONAL` if never independently observed).
    pub pid: u32,
    pub uid: u32,
    /// From the outer `auid=`. `None` when the record omits it or prints
    /// the unset sentinel — systemd does not always have an actor's login
    /// uid to report (e.g. a unit started at boot, with no D-Bus caller).
    pub auid: Option<u32>,
    /// From the outer `ses=`. `None` when absent/unset. When present, this
    /// is the *direct observation* `normalize_systemd_event` uses to
    /// populate `CanonicalEvent.session` (plan Global Constraint #3) —
    /// exactly the same pattern `PrivilegeEventRaw.session_id` already
    /// established in Phase 4a.
    pub session_id: Option<String>,
    /// From the nested `res=`: `res=success` -> true.
    pub success: bool,
    /// From the nested `exe=`, full path (typically
    /// `/usr/lib/systemd/systemd`).
    pub exe_path: String,
    /// From the nested `comm=` (typically `"systemd"`).
    pub comm: String,
    pub timestamp_ns: u64,
    pub audit_serial: Option<u64>,
    pub source: RawEventSource,
}

/// Which of Persistence Monitor's config-declared watch targets a changed
/// path belongs to (plan Global Constraint #4). Explicitly set by the
/// sensor from its own config — never inferred by pattern-matching the path
/// string. `SystemdUnit`/`SystemdTimer` are the one place this phase
/// distinguishes *within* a single watch target, by file extension, since a
/// `systemd_unit_dir` target's directory holds both kinds of file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistenceCheckpointKind {
    SystemdUnit,
    SystemdTimer,
    Cron,
    ShellProfile,
    LdPreload,
    Sudoers,
}

/// The three lifecycle transitions Persistence Monitor's periodic scan-and-
/// diff observes for one watched path (plan Global Constraint #8: the very
/// first scan after Agent start seeds a baseline silently and emits none of
/// these for whatever it finds already present).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistenceOperation {
    Created,
    Modified,
    Removed,
}

/// A persistence-checkpoint-path lifecycle record, from Persistence
/// Monitor's periodic scan (never from Linux Audit — plan Global Constraint
/// #1). No process/session identity is ever attached: the scanner is not
/// triggered by a process event, so any pid it reported would be
/// fabricated. `content_hash`/`size` are always `None` for `Removed` (there
/// is nothing left to hash — plan-mandated, not an oversight).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEventRaw {
    pub operation: PersistenceOperation,
    pub checkpoint_kind: PersistenceCheckpointKind,
    pub path: String,
    /// SHA-256 hex digest of the file's current content. `None` for
    /// `Removed`.
    pub content_hash: Option<String>,
    /// `None` for `Removed`.
    pub size: Option<u64>,
    pub timestamp_ns: u64,
    /// Always `RawEventSource::Procfs` in practice (plan Global Constraint
    /// #1 — no audit-log equivalent exists for a generic file-content
    /// scan); kept as the full enum rather than hardcoded so a future
    /// fanotify-backed variant is a value change here, not a type change.
    pub source: RawEventSource,
}
```

- [ ] **Step 4: Add the two `RawEvent` variants**

In `crates/osiris-sensor-api/src/raw_event.rs`'s `RawEvent` enum:

```rust
pub enum RawEvent {
    ProcessExec(ProcessExecRaw),
    File(FileEventRaw),
    Network(NetworkEventRaw),
    Dns(DnsEventRaw),
    Identity(IdentityEventRaw),
    Privilege(PrivilegeEventRaw),
    Systemd(SystemdEventRaw),
    Persistence(PersistenceEventRaw),
}
```

And in `impl RawEvent`'s `timestamp_ns` match:

```rust
            RawEvent::Systemd(s) => s.timestamp_ns,
            RawEvent::Persistence(p) => p.timestamp_ns,
```

- [ ] **Step 5: Re-export from the crate root**

In `crates/osiris-sensor-api/src/lib.rs`, extend the `pub use raw_event::{...}` list with:

```rust
    PersistenceCheckpointKind, PersistenceEventRaw, PersistenceOperation, SystemdEventRaw,
    SystemdOperation,
```

(keep the existing alphabetized entries; insert these among them consistently with the list's current ordering convention).

- [ ] **Step 6: Run the tests**

Run: `cargo test -p osiris-sensor-api`
Expected: PASS — all new tests plus every pre-existing test in this crate.

- [ ] **Step 7: Build only this crate — do NOT run a full-workspace build yet**

Run: `cargo build -p osiris-sensor-api --all-targets`
Expected: PASS.

**Do not run `cargo build --workspace --all-targets` in this task.** `crates/osiris-pipeline/src/normalize.rs` has an exhaustive `match raw { RawEvent::ProcessExec(p) => ..., ... }` over every `RawEvent` variant, with no wildcard arm — adding `RawEvent::Systemd`/`RawEvent::Persistence` here makes that match non-exhaustive, so `osiris-pipeline` (and everything downstream of it: `osiris-agent`, `osiris-server`, `osiris-e2e-tests`) will fail to compile until Task 4 adds the two new match arms there. This is a deliberate, known, one-task-wide gap in `cargo build --workspace`'s green state — the same situation Phase 4a's own Task 1 (`RawEvent::Identity`/`RawEvent::Privilege`) created and Task 2 resolved next. State this explicitly in the task report so the reviewer verifies `-p osiris-sensor-api` build/test evidence for *this* task and does not flag the expected workspace-wide break as a regression; Task 4's own report is where full-workspace-build evidence belongs.

- [ ] **Step 8: Commit**

```bash
git add crates/osiris-sensor-api/src/lib.rs crates/osiris-sensor-api/src/raw_event.rs
git commit -m "feat(sensor-api): RawEvent::Systemd and RawEvent::Persistence"
```

## Task 4: `osiris-pipeline` — normalize Systemd/Persistence, no new relation edges

**Files:**
- Modify: `crates/osiris-pipeline/src/normalize.rs`
- Modify: `crates/osiris-pipeline/src/pipeline.rs` (tests only)

**Interfaces:**
- Consumes: Task 3's `SystemdEventRaw`/`PersistenceEventRaw`/`SystemdOperation`/`PersistenceOperation`/`PersistenceCheckpointKind`; Task 1's fixed `attach_session`.
- Produces: `normalize()` handles `RawEvent::Systemd`/`RawEvent::Persistence`, populating `CanonicalEvent.service: Some(ServiceRef{..})` for Systemd-category results (both from the audit-backed sensor's `ServiceStart`/`ServiceStop`, and from Persistence Monitor's unit-file-lifecycle results per Global Constraint #1) and `CanonicalEvent.file: Some(FileRef{..})` for Persistence-category results. **No changes to `enrich.rs`'s relation-edge `match` in this task** — Global Constraint #3 is a plan-wide ruling, not something this task revisits function-by-function; `enrich::enrich`'s `match event.category { Category::File => ..., ... }` for relationship attachment is left completely untouched (no `Category::Systemd`/`Category::Persistence` arm is added).

**Before writing any code**, re-read `crates/osiris-pipeline/src/normalize.rs`'s `normalize_privilege_event` (the closest existing template: direct `session` observation from `ses=`, `build_user_ref`, `provisional_process`) and confirm its exact current shape — this task's two new functions mirror it, not `normalize_identity_event`.

- [ ] **Step 1: Write the failing normalize tests**

Append to `crates/osiris-pipeline/src/normalize.rs`'s `#[cfg(test)] mod tests`:

```rust
    fn systemd_start_raw() -> SystemdEventRaw {
        SystemdEventRaw {
            operation: SystemdOperation::Start,
            unit_name: "backdoor.service".to_string(),
            pid: 1,
            uid: 0,
            auid: Some(1000),
            session_id: Some("3".to_string()),
            success: true,
            exe_path: "/usr/lib/systemd/systemd".to_string(),
            comm: "systemd".to_string(),
            timestamp_ns: 1_000,
            audit_serial: Some(501),
            source: RawEventSource::Audit,
        }
    }

    #[test]
    fn normalizes_a_systemd_start_event_with_directly_observed_session() {
        let host = test_host();
        let event = normalize(RawEvent::Systemd(systemd_start_raw()), &host, "boot-1");
        assert_eq!(event.event_type, EventType::ServiceStart);
        assert_eq!(event.category, Category::Systemd);
        let service = event.service.as_ref().expect("service must be set");
        assert_eq!(service.unit_name, "backdoor.service");
        assert_eq!(service.unit_type, "service");
        assert_eq!(service.action, "start");
        assert_eq!(
            event.session.as_ref().expect("session must be observed").session_id,
            "3"
        );
        assert_eq!(event.user.as_ref().unwrap().uid, 0);
    }

    #[test]
    fn normalizes_a_systemd_stop_event_for_a_timer_unit() {
        let host = test_host();
        let mut raw = systemd_start_raw();
        raw.operation = SystemdOperation::Stop;
        raw.unit_name = "backdoor.timer".to_string();
        let event = normalize(RawEvent::Systemd(raw), &host, "boot-1");
        assert_eq!(event.event_type, EventType::ServiceStop);
        let service = event.service.as_ref().unwrap();
        assert_eq!(service.unit_type, "timer");
        assert_eq!(service.action, "stop");
    }

    #[test]
    fn a_systemd_event_with_no_observed_session_gets_none_not_a_guess() {
        let host = test_host();
        let mut raw = systemd_start_raw();
        raw.session_id = None;
        let event = normalize(RawEvent::Systemd(raw), &host, "boot-1");
        assert!(event.session.is_none());
    }

    fn persistence_raw(
        operation: PersistenceOperation,
        checkpoint_kind: PersistenceCheckpointKind,
        path: &str,
    ) -> PersistenceEventRaw {
        PersistenceEventRaw {
            operation,
            checkpoint_kind,
            path: path.to_string(),
            content_hash: match operation {
                PersistenceOperation::Removed => None,
                _ => Some("a".repeat(64)),
            },
            size: match operation {
                PersistenceOperation::Removed => None,
                _ => Some(64),
            },
            timestamp_ns: 2_000,
            source: RawEventSource::Procfs,
        }
    }

    #[test]
    fn a_new_systemd_unit_file_normalizes_to_service_create_not_persistence() {
        let host = test_host();
        let raw = persistence_raw(
            PersistenceOperation::Created,
            PersistenceCheckpointKind::SystemdUnit,
            "/etc/systemd/system/backdoor.service",
        );
        let event = normalize(RawEvent::Persistence(raw), &host, "boot-1");
        assert_eq!(event.event_type, EventType::ServiceCreate);
        assert_eq!(event.category, Category::Systemd);
        let service = event.service.as_ref().expect("service must be set");
        assert_eq!(service.unit_name, "backdoor.service");
        assert_eq!(service.unit_type, "service");
        assert_eq!(service.action, "create");
        // Unit-file-lifecycle events are still FileRef-carrying too — the
        // path/hash is real, observable data, and Task 10's Systemd Story
        // does not need it, but nothing forbids keeping it honestly.
        assert_eq!(
            event.file.as_ref().unwrap().path,
            "/etc/systemd/system/backdoor.service"
        );
    }

    #[test]
    fn a_modified_systemd_timer_file_normalizes_to_timer_modify() {
        let host = test_host();
        let raw = persistence_raw(
            PersistenceOperation::Modified,
            PersistenceCheckpointKind::SystemdTimer,
            "/etc/systemd/system/backdoor.timer",
        );
        let event = normalize(RawEvent::Persistence(raw), &host, "boot-1");
        assert_eq!(event.event_type, EventType::TimerModify);
        assert_eq!(event.category, Category::Systemd);
        assert_eq!(event.service.as_ref().unwrap().unit_type, "timer");
    }

    /// Global Constraint #5: there is no TIMER_DELETE in the frozen
    /// taxonomy, so a removed timer file normalizes to TIMER_MODIFY with
    /// the true operation disclosed in event_data, never invented as a new
    /// enum variant and never silently conflated with an actual edit
    /// without that disclosure.
    #[test]
    fn a_removed_systemd_timer_file_normalizes_to_timer_modify_with_operation_disclosed() {
        let host = test_host();
        let raw = persistence_raw(
            PersistenceOperation::Removed,
            PersistenceCheckpointKind::SystemdTimer,
            "/etc/systemd/system/backdoor.timer",
        );
        let event = normalize(RawEvent::Persistence(raw), &host, "boot-1");
        assert_eq!(event.event_type, EventType::TimerModify);
        assert_eq!(
            event.event_data.get("operation").and_then(|v| v.as_str()),
            Some("removed")
        );
    }

    #[test]
    fn a_new_cron_file_normalizes_to_generic_persistence_created() {
        let host = test_host();
        let raw = persistence_raw(
            PersistenceOperation::Created,
            PersistenceCheckpointKind::Cron,
            "/etc/cron.d/backdoor",
        );
        let event = normalize(RawEvent::Persistence(raw), &host, "boot-1");
        assert_eq!(event.event_type, EventType::PersistenceCreated);
        assert_eq!(event.category, Category::Persistence);
        assert!(event.service.is_none());
        assert_eq!(event.file.as_ref().unwrap().path, "/etc/cron.d/backdoor");
    }

    #[test]
    fn a_removed_ld_preload_normalizes_to_persistence_removed_with_no_hash() {
        let host = test_host();
        let raw = persistence_raw(
            PersistenceOperation::Removed,
            PersistenceCheckpointKind::LdPreload,
            "/etc/ld.so.preload",
        );
        let event = normalize(RawEvent::Persistence(raw), &host, "boot-1");
        assert_eq!(event.event_type, EventType::PersistenceRemoved);
        assert!(event.file.as_ref().unwrap().hash.is_none());
    }

    /// Persistence-category events carry no process/session identity — the
    /// scanner is not triggered by a process event (plan Global Constraint
    /// #3), and inventing either would be exactly the fabrication this
    /// codebase's discipline forbids everywhere else.
    #[test]
    fn a_persistence_event_carries_no_process_or_session() {
        let host = test_host();
        let raw = persistence_raw(
            PersistenceOperation::Created,
            PersistenceCheckpointKind::Sudoers,
            "/etc/sudoers.d/backdoor",
        );
        let event = normalize(RawEvent::Persistence(raw), &host, "boot-1");
        assert!(event.process.is_none());
        assert!(event.session.is_none());
        assert!(event.user.is_none());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p osiris-pipeline`
Expected: FAIL to compile — `normalize` has no arm for `RawEvent::Systemd`/`RawEvent::Persistence` yet (non-exhaustive match is a compile error, not a runtime one, so this is the "red" state).

- [ ] **Step 3: Extend the top-of-file imports**

In `crates/osiris-pipeline/src/normalize.rs`, extend the two `use` blocks:

```rust
use osiris_schema::{
    CanonicalEvent, Category, DnsRef, EventType, FileRef, HostRef, NetworkDirection, NetworkRef,
    ProcessKey, ProcessRef, ServiceRef, SessionRef, Severity, Source, UserRef, SCHEMA_VERSION,
};
use osiris_sensor_api::{
    DnsEventRaw, FileEventRaw, FileOperation, IdentityEventRaw, IdentityOperation,
    NetworkDirection as RawNetworkDirection, NetworkEventRaw, NetworkOperation,
    PersistenceCheckpointKind, PersistenceEventRaw, PersistenceOperation, PrivilegeEventRaw,
    PrivilegeOperation, ProcessExecRaw, RawEvent, RawEventSource, SystemdEventRaw,
    SystemdOperation,
};
```

- [ ] **Step 4: Add the two dispatch arms**

In `normalize()`'s match:

```rust
        RawEvent::Systemd(s) => normalize_systemd_event(s, host, boot_id),
        RawEvent::Persistence(p) => normalize_persistence_event(p, host, boot_id),
```

- [ ] **Step 5: Implement `normalize_systemd_event`**

Append after `normalize_privilege_event`:

```rust
fn normalize_systemd_event(raw: SystemdEventRaw, host: &HostRef, boot_id: &str) -> CanonicalEvent {
    let event_type = match raw.operation {
        SystemdOperation::Start => EventType::ServiceStart,
        SystemdOperation::Stop => EventType::ServiceStop,
    };
    let (user, partial) = build_user_ref(raw.uid, None, None, None, None, raw.auid);
    let mut tags = Vec::new();
    if partial {
        tags.push("USER_REF_PARTIAL".to_string());
    }
    // A minimal SessionRef from the record's own `ses=` — the same
    // direct-observation pattern `normalize_privilege_event` established in
    // Phase 4a. The Enrich stage's now-fixed `attach_session` (Task 1)
    // prefers this over any pid/ppid-inferred session, and enriches it
    // further when that session's login was itself observed.
    let session = raw.session_id.clone().map(|session_id| SessionRef {
        session_id,
        tty: None,
        remote_addr: None,
        auth_method: None,
    });
    let unit_type = unit_type_from_name(&raw.unit_name);
    let action = match raw.operation {
        SystemdOperation::Start => "start",
        SystemdOperation::Stop => "stop",
    };
    // Genuinely systemd's own pid on a real host (plan Global Constraint
    // #3's disclosure) — kept honestly, not discarded, so it still resolves
    // through the ordinary ProcessResolver/PROCESS_KEY_PROVISIONAL path
    // like any other pid nothing independently observed an exec for.
    let process = provisional_process(Some(raw.pid), &raw.exe_path, host.host_id, boot_id);
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host.host_id,
        boot_id: boot_id.to_string(),
        timestamp: raw.timestamp_ns,
        monotonic_timestamp: raw.timestamp_ns,
        event_type,
        category: Category::Systemd,
        severity: Severity::Info,
        host: host.clone(),
        user: Some(user),
        session,
        process,
        parent_process: None,
        thread: None,
        file: None,
        network: None,
        dns: None,
        device: None,
        service: Some(ServiceRef {
            unit_name: raw.unit_name,
            unit_type: unit_type.to_string(),
            action: action.to_string(),
        }),
        container: None,
        namespace: None,
        cgroup: None,
        kernel: None,
        source: schema_source(raw.source),
        provider: "systemd_sensor/audit".to_string(),
        raw_event: None,
        relationships: vec![],
        tags,
        risk: None,
        event_data: serde_json::json!({
            "comm": raw.comm,
            "auid": raw.auid,
            "success": raw.success,
            "audit_serial": raw.audit_serial,
        }),
    }
}

/// `.timer` -> `"timer"`, anything else -> `"service"` — the only two unit
/// types this phase's sensor and monitor ever report (plan Global
/// Constraint #4: a `systemd_unit_dir` watch target's non-`.service`/
/// `.timer` files are silently skipped upstream, so this function never
/// sees them).
fn unit_type_from_name(unit_name: &str) -> &'static str {
    if unit_name.ends_with(".timer") {
        "timer"
    } else {
        "service"
    }
}
```

- [ ] **Step 6: Implement `normalize_persistence_event` and its category-classification helper**

Append after `normalize_systemd_event`:

```rust
fn normalize_persistence_event(
    raw: PersistenceEventRaw,
    host: &HostRef,
    boot_id: &str,
) -> CanonicalEvent {
    let (event_type, category, service, disclosed_operation) = classify_persistence_event(&raw);
    let mut event_data = serde_json::json!({
        "checkpoint_kind": raw.checkpoint_kind,
    });
    if let Some(operation) = disclosed_operation {
        event_data["operation"] = serde_json::Value::String(operation.to_string());
    }
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host.host_id,
        boot_id: boot_id.to_string(),
        timestamp: raw.timestamp_ns,
        monotonic_timestamp: raw.timestamp_ns,
        event_type,
        category,
        severity: Severity::Info,
        host: host.clone(),
        // No process/session/user identity: the scanner observed a path on
        // disk, not a process's action (plan Global Constraint #3). An
        // invented actor here would be exactly the fabrication this
        // codebase's discipline forbids for file/network/privilege
        // identity elsewhere.
        user: None,
        session: None,
        process: None,
        parent_process: None,
        thread: None,
        file: Some(FileRef {
            path: raw.path,
            previous_path: None,
            inode: None,
            device_id: None,
            size: raw.size,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: raw.content_hash,
        }),
        network: None,
        dns: None,
        device: None,
        service,
        container: None,
        namespace: None,
        cgroup: None,
        kernel: None,
        source: schema_source(raw.source),
        provider: "persistence_sensor/procfs".to_string(),
        raw_event: None,
        relationships: vec![],
        tags: vec![],
        risk: None,
        event_data,
    }
}

/// Maps a Persistence Monitor result to its taxonomy home (plan Global
/// Constraints #1/#5). A `SystemdUnit`/`SystemdTimer` checkpoint is a
/// SYSTEMD-category unit-*file*-lifecycle event; every other checkpoint
/// kind is a PERSISTENCE-category event. One path maps to exactly one
/// category, never both, so a unit file's own creation is never
/// double-counted as generic persistence too. Returns the disclosed
/// operation string (Global Constraint #5) only for the one case where the
/// frozen `EventType` can't distinguish it from a real modification
/// (a removed `.timer` file, mapped to `TimerModify`) — `None` everywhere
/// else, since every other mapping's `event_type` already names its own
/// operation precisely.
fn classify_persistence_event(
    raw: &PersistenceEventRaw,
) -> (EventType, Category, Option<ServiceRef>, Option<&'static str>) {
    use PersistenceCheckpointKind::*;
    use PersistenceOperation::*;
    match raw.checkpoint_kind {
        SystemdUnit | SystemdTimer => {
            let unit_name = unit_name_from_path(&raw.path);
            let unit_type = if raw.checkpoint_kind == SystemdTimer {
                "timer"
            } else {
                "service"
            };
            let (event_type, action, disclosed) = match (raw.checkpoint_kind, raw.operation) {
                (SystemdUnit, Created) => (EventType::ServiceCreate, "create", None),
                (SystemdUnit, Modified) => (EventType::ServiceModify, "modify", None),
                (SystemdUnit, Removed) => (EventType::ServiceDelete, "delete", None),
                (SystemdTimer, Created) => (EventType::TimerCreate, "create", None),
                (SystemdTimer, Modified) => (EventType::TimerModify, "modify", None),
                // Global Constraint #5: no TIMER_DELETE exists in the
                // frozen taxonomy. TIMER_MODIFY stands in, with the real
                // operation disclosed in event_data so nothing downstream
                // mistakes a removal for an edit.
                (SystemdTimer, Removed) => (EventType::TimerModify, "delete", Some("removed")),
                (SystemdUnit, _) | (Cron | ShellProfile | LdPreload | Sudoers, _) => {
                    unreachable!("outer match already narrowed to SystemdUnit | SystemdTimer")
                }
            };
            (
                event_type,
                Category::Systemd,
                Some(ServiceRef {
                    unit_name,
                    unit_type: unit_type.to_string(),
                    action: action.to_string(),
                }),
                disclosed,
            )
        }
        Cron | ShellProfile | LdPreload | Sudoers => {
            let event_type = match raw.operation {
                Created => EventType::PersistenceCreated,
                Modified => EventType::PersistenceModified,
                Removed => EventType::PersistenceRemoved,
            };
            (event_type, Category::Persistence, None, None)
        }
    }
}

/// The file stem of a unit-file path — matches `basename`'s job in the
/// identity sensor's own parser, but this one operates on a full
/// filesystem path from the scanner, not an auditd `exe=` field, so it is
/// not worth sharing (different input shape, same one-liner either way).
fn unit_name_from_path(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p osiris-pipeline`
Expected: PASS — all new tests, and every pre-existing `normalize.rs`/`enrich.rs`/`pipeline.rs` test still green.

- [ ] **Step 8: Add the whole-pipeline integration test**

Append to `crates/osiris-pipeline/src/pipeline.rs`'s `#[cfg(test)] mod tests`:

```rust
    /// The whole Normalize -> Enrich -> Validate -> Prioritize path for a
    /// Systemd event whose `ses=` matches an already-open session — proof
    /// that Task 1's fix plus this task's direct-observation normalize
    /// combine to make Global Constraint #3's "free" cross-category
    /// correlation real, not just unit-tested in isolation.
    #[test]
    fn a_systemd_service_start_inherits_no_pid_but_keeps_its_observed_session() {
        use osiris_sensor_api::{
            IdentityEventRaw, IdentityOperation, SystemdEventRaw, SystemdOperation,
        };
        let host = test_host();
        let mut pipeline = Pipeline::new(host.clone(), "boot-1".to_string());

        let _sshd = pipeline.process(RawEvent::ProcessExec(ProcessExecRaw {
            pid: 100,
            ppid: 1,
            uid: 0,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: 1_000,
            start_time_mono: 1_000,
            source: RawEventSource::Synthetic,
        }));
        let _login = pipeline.process(RawEvent::Identity(IdentityEventRaw {
            operation: IdentityOperation::Login,
            session_id: "3".to_string(),
            pid: 100,
            uid: 0,
            auid: Some(1000),
            username: Some("alice".to_string()),
            terminal: Some("/dev/pts/0".to_string()),
            remote_addr: Some("198.51.100.10".to_string()),
            auth_method: Some("sshd".to_string()),
            success: true,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: 2_000,
            audit_serial: Some(456),
            source: RawEventSource::Synthetic,
        }));

        // The systemd service-start record's own outer pid is 1 (systemd
        // itself) — unrelated to pid 100/sshd's ancestry entirely. Its
        // session attribution comes ONLY from its own observed `ses=`.
        let start = pipeline.process(RawEvent::Systemd(SystemdEventRaw {
            operation: SystemdOperation::Start,
            unit_name: "backdoor.service".to_string(),
            pid: 1,
            uid: 0,
            auid: Some(1000),
            session_id: Some("3".to_string()),
            success: true,
            exe_path: "/usr/lib/systemd/systemd".to_string(),
            comm: "systemd".to_string(),
            timestamp_ns: 3_000,
            audit_serial: Some(501),
            source: RawEventSource::Synthetic,
        }));

        assert!(!start.event.tags.contains(&"INVALID".to_string()));
        let session = start.event.session.expect("session must be observed");
        assert_eq!(session.session_id, "3");
        assert_eq!(
            session.remote_addr.as_deref(),
            Some("198.51.100.10"),
            "the systemd event must be enriched to the full session record, \
             which is what makes Task 9's rule expressible"
        );
    }
```

- [ ] **Step 9: Run the full pipeline test suite**

Run: `cargo test -p osiris-pipeline`
Expected: PASS — including the new integration test.

- [ ] **Step 10: Run the full workspace build**

Run: `cargo build --workspace --all-targets`
Expected: PASS — this is the task where `osiris-pipeline`'s `normalize()` becomes exhaustive again, so this is the first point since Task 3 where the whole workspace compiles. Confirm it now does.

- [ ] **Step 11: Commit**

```bash
git add crates/osiris-pipeline/src/normalize.rs crates/osiris-pipeline/src/pipeline.rs
git commit -m "feat(pipeline): normalize Systemd and Persistence events, no new relation edges"
```

## Task 5: `osiris-sensors-systemd` — the audit-backed Systemd sensor

**Files:**
- Create: `crates/osiris-sensors/systemd/Cargo.toml`
- Create: `crates/osiris-sensors/systemd/src/lib.rs`
- Create: `crates/osiris-sensors/systemd/src/audit_record.rs`
- Create: `crates/osiris-sensors/systemd/src/sensor.rs`
- Modify: `Cargo.toml` (workspace root — add the new crate to `members`)
- Modify: `tools/check-dep-graph.sh` (add the forbidden-dependency check)

**Interfaces:**
- Consumes: Task 2's shared `osiris_fileutil::{RecordParts, split_record, parse_id, usable_session}`; Task 3's `SystemdEventRaw`/`SystemdOperation`/`RawEventSource`; `osiris_fileutil::LineTailer` (unchanged, already exists).
- Produces: `osiris_sensors_systemd::SystemdSensor::new(audit_log_path: impl Into<PathBuf>) -> Self`, `.with_poll_interval(Duration) -> Self`, implementing the `Sensor` trait. Task 8 wires this into `osiris-agent`.

**Before writing any code**, open `crates/osiris-sensors/identity/src/sensor.rs` in full and confirm its exact current shape — this task's `sensor.rs` mirrors it structurally (health state, capability probing, `LineTailer` polling loop, emit helper), with the only real differences being the parser it calls and the single `RawEvent::Systemd` variant it emits (no `IdentityRecord`-style two-variant wrapper is needed, since this sensor only ever emits one `RawEvent` shape).

- [ ] **Step 1: Register the new crate in the workspace**

In the workspace-root `Cargo.toml`, extend `members`:

```toml
members = ["crates/*", "crates/osiris-sensors/process", "crates/osiris-sensors/fs", "crates/osiris-sensors/net", "crates/osiris-sensors/identity", "crates/osiris-sensors/systemd", "crates/osiris-sensors/persistence", "generator"]
```

(This also registers Task 6's `osiris-sensors-persistence` — both new crates are added in this one edit since the `members` array only needs touching once; Task 6 does not repeat this step.)

Create `crates/osiris-sensors/systemd/Cargo.toml`:

```toml
[package]
name = "osiris-sensors-systemd"
version.workspace = true
edition.workspace = true

[dependencies]
tokio = { workspace = true }
tokio-util = { workspace = true }
async-trait = { workspace = true }
osiris-sensor-api = { path = "../../osiris-sensor-api" }
osiris-fileutil = { path = "../../osiris-fileutil" }

[dev-dependencies]
tempfile = { workspace = true }
```

Create an empty placeholder `crates/osiris-sensors/systemd/src/lib.rs` (filled in Step 6) and confirm the crate registers:

Run: `cargo build -p osiris-sensors-systemd`
Expected: PASS (empty crate, nothing to fail on yet — this only proves the workspace member registration and manifest are correct).

- [ ] **Step 2: Add the dependency-graph check**

In `tools/check-dep-graph.sh`, add immediately after `check_forbidden osiris-sensors-identity osiris-server osiris-api`:

```bash
check_forbidden osiris-sensors-systemd osiris-server osiris-api
```

Run: `bash tools/check-dep-graph.sh`
Expected: `skip: osiris-sensors-systemd not in workspace yet` transitions to a real check once Step 6 gives the crate real dependencies — for now, confirm the script still runs and passes (the `crate_exists` guard means an empty/near-empty crate with no forbidden deps trivially passes).

- [ ] **Step 3: Write the failing parser tests**

Create `crates/osiris-sensors/systemd/src/audit_record.rs`. Real, documented auditd behavior this parser relies on (verified before writing this plan, same rigor bar every earlier phase held): systemd emits `type=SERVICE_START`/`type=SERVICE_STOP` audit records via `audit_log_user_comm_message` when the audit subsystem is enabled, one record per unit start/stop. The outer body carries `pid=`/`uid=`/`auid=`/`ses=` exactly like Identity/Privilege's `USER_*` records; the nested, single-quoted `msg='...'` sub-record carries `unit=`, `comm=`, `exe=`, `hostname=`, `addr=`, `terminal=`, `res=`. This is the identical two-layer shape Task 2's shared `split_record` already handles — nothing new to parse structurally, only new field names to extract.

```rust
use osiris_fileutil::{parse_id, split_record, usable_session, RecordParts};
use osiris_sensor_api::{RawEventSource, SystemdEventRaw, SystemdOperation};

/// Parses one auditd line into a `SystemdEventRaw`, or `None` when the line
/// is not a `SERVICE_START`/`SERVICE_STOP` record, or is one but is missing
/// a field this parser requires (`unit=`, `pid=`, `uid=`) — never a panic,
/// never a half-built event.
pub fn parse_record(line: &str) -> Option<SystemdEventRaw> {
    let parts = split_record(line)?;
    let operation = match parts.record_type.as_str() {
        "SERVICE_START" => SystemdOperation::Start,
        "SERVICE_STOP" => SystemdOperation::Stop,
        _ => return None,
    };
    let unit_name = parts.get("unit")?.to_string();
    let exe_path = parts.get("exe").unwrap_or_default().to_string();
    Some(SystemdEventRaw {
        operation,
        unit_name,
        pid: parts.get("pid")?.parse().ok()?,
        uid: parts.get("uid")?.parse().ok()?,
        auid: parse_id(parts.get("auid")),
        session_id: usable_session(parts.get("ses")),
        success: parts.get("res") == Some("success"),
        comm: parts.get("comm").unwrap_or_default().to_string(),
        exe_path,
        timestamp_ns: parts.id.timestamp_ns,
        audit_serial: Some(parts.id.serial),
        source: RawEventSource::Audit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE_START: &str = r#"type=SERVICE_START msg=audit(1690000000.123:501): pid=1 uid=0 auid=1000 ses=3 subj=unconfined msg='unit=backdoor.service comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'"#;
    const SERVICE_STOP: &str = r#"type=SERVICE_STOP msg=audit(1690000010.456:512): pid=1 uid=0 auid=1000 ses=3 subj=unconfined msg='unit=backdoor.service comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'"#;
    const SERVICE_START_NO_SESSION: &str = r#"type=SERVICE_START msg=audit(1690000000.123:501): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='unit=sshd.service comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'"#;

    #[test]
    fn parses_a_service_start_record() {
        let raw = parse_record(SERVICE_START).expect("must parse");
        assert_eq!(raw.operation, SystemdOperation::Start);
        assert_eq!(raw.unit_name, "backdoor.service");
        assert_eq!(raw.pid, 1);
        assert_eq!(raw.uid, 0);
        assert_eq!(raw.auid, Some(1000));
        assert_eq!(raw.session_id.as_deref(), Some("3"));
        assert!(raw.success);
        assert_eq!(raw.comm, "systemd");
        assert_eq!(raw.exe_path, "/usr/lib/systemd/systemd");
        assert_eq!(raw.timestamp_ns, 1_690_000_000_123_000_000);
        assert_eq!(raw.audit_serial, Some(501));
    }

    #[test]
    fn parses_a_service_stop_record() {
        let raw = parse_record(SERVICE_STOP).expect("must parse");
        assert_eq!(raw.operation, SystemdOperation::Stop);
        assert_eq!(raw.unit_name, "backdoor.service");
    }

    /// Unlike Identity's `USER_LOGIN`, a session-less SERVICE_START is NOT
    /// dropped — a unit started at boot, before any login, genuinely has no
    /// session to report, and that is still a real, storable Systemd event
    /// (unlike a failed login, nothing here depends on a session existing
    /// to be meaningful).
    #[test]
    fn a_session_less_service_start_is_still_parsed_with_session_id_none() {
        let raw = parse_record(SERVICE_START_NO_SESSION).expect("must parse");
        assert!(raw.session_id.is_none());
        assert!(raw.auid.is_none());
    }

    #[test]
    fn ignores_records_of_other_types() {
        assert!(parse_record(
            r#"type=SERVICE_RELOAD msg=audit(1690000000.123:501): pid=1 uid=0"#
        )
        .is_none());
        assert!(parse_record("not an audit record at all").is_none());
    }

    #[test]
    fn returns_none_when_the_required_unit_field_is_missing() {
        assert!(parse_record(
            r#"type=SERVICE_START msg=audit(1690000000.123:501): pid=1 uid=0 msg='comm="systemd" res=success'"#
        )
        .is_none());
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p osiris-sensors-systemd`
Expected: PASS immediately — unlike a TDD red/green pair on existing code, this parser is new and self-contained; write it once, correctly, and confirm.

- [ ] **Step 5: Write the sensor**

Create `crates/osiris-sensors/systemd/src/sensor.rs`, mirroring `osiris-sensors-identity`'s `sensor.rs` structure exactly (health state struct, `lock_health` helper, capability probing on `audit_log_path.exists()`, a `tokio::spawn`ed `LineTailer`-polling loop, `stop`/`health`/`metrics`) with these differences: `name()` returns `"systemd"`; the emit helper takes a `SystemdEventRaw` directly and wraps it `RawEvent::Systemd(raw)` (no `IdentityRecord`-style two-variant enum, since `crate::audit_record::parse_record` only ever produces one shape); the polling loop calls `crate::audit_record::parse_record(&line)` instead of the identity crate's `parse_record`. Copy the identity sensor's `struct HealthState`, `impl Default for HealthState`, and `fn lock_health` verbatim (character-for-character) — they have no identity-specific content at all.

```rust
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use osiris_fileutil::LineTailer;
use osiris_sensor_api::{
    RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth, SensorMetrics,
    SensorState,
};
use tokio_util::sync::CancellationToken;

use crate::audit_record::parse_record;

struct HealthState {
    state: SensorState,
    events_emitted_total: u64,
    events_dropped_total: u64,
    last_error: Option<String>,
    last_event_at: Option<u64>,
    capability_flags: Vec<String>,
}

impl Default for HealthState {
    fn default() -> Self {
        Self {
            state: SensorState::Starting,
            events_emitted_total: 0,
            events_dropped_total: 0,
            last_error: None,
            last_event_at: None,
            capability_flags: vec![],
        }
    }
}

fn lock_health(health: &Mutex<HealthState>) -> MutexGuard<'_, HealthState> {
    health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The Systemd sensor (ARCHITECTURE.md §4.3's Systemd row), this phase's
/// scope: the Linux Audit backend only (plan Global Constraint #1) — real,
/// documented `SERVICE_START`/`SERVICE_STOP` records systemd itself emits,
/// consumed by tailing an auditd-format log file. D-Bus subscription and
/// `systemctl list-units` polling are NOT implemented (see the plan's
/// Global Constraint #1 for why); those are additional `Sensor`
/// implementations behind this same unchanged trait, not a rewrite.
pub struct SystemdSensor {
    audit_log_path: PathBuf,
    poll_interval: Duration,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
}

impl SystemdSensor {
    pub fn new(audit_log_path: impl Into<PathBuf>) -> Self {
        Self {
            audit_log_path: audit_log_path.into(),
            poll_interval: Duration::from_millis(200),
            cancellation: None,
            task_handle: None,
            health: Arc::new(Mutex::new(HealthState::default())),
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }
}

#[async_trait]
impl Sensor for SystemdSensor {
    fn name(&self) -> &'static str {
        "systemd"
    }

    fn capabilities(&self) -> SensorCapabilities {
        if self.audit_log_path.exists() {
            SensorCapabilities {
                ebpf: false,
                audit_fallback: true,
                always_available: false,
                unsupported_reason: None,
            }
        } else {
            SensorCapabilities {
                ebpf: false,
                audit_fallback: false,
                always_available: false,
                unsupported_reason: Some(format!(
                    "audit log not found at {}",
                    self.audit_log_path.display()
                )),
            }
        }
    }

    async fn initialize(&mut self, ctx: SensorContext) -> Result<(), SensorError> {
        self.cancellation = Some(ctx.cancellation.clone());
        lock_health(&self.health).state = SensorState::Starting;

        let caps = self.capabilities();
        if !caps.supported() {
            let reason = caps.unsupported_reason.clone().unwrap_or_default();
            lock_health(&self.health).last_error = Some(reason.clone());
            return Err(SensorError::Unsupported(reason));
        }
        lock_health(&self.health).capability_flags = vec!["audit_fallback".to_string()];

        let path = self.audit_log_path.clone();
        let poll_interval = self.poll_interval;
        let output = ctx.output;
        let cancellation = ctx.cancellation;
        let health = self.health.clone();

        let handle = tokio::spawn(async move {
            let mut tailer = LineTailer::new(path);
            loop {
                if cancellation.is_cancelled() {
                    lock_health(&health).state = SensorState::Stopped;
                    return;
                }
                match tailer.poll() {
                    Ok(lines) => {
                        for line in lines {
                            if let Some(raw) = parse_record(&line) {
                                emit(&output, raw, &health).await;
                            }
                        }
                    }
                    Err(e) => {
                        let mut h = lock_health(&health);
                        h.state = SensorState::Degraded;
                        h.last_error = Some(e.to_string());
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {}
                    _ = cancellation.cancelled() => {
                        lock_health(&health).state = SensorState::Stopped;
                        return;
                    }
                }
            }
        });
        self.task_handle = Some(handle);
        Ok(())
    }

    async fn start(&mut self) -> Result<(), SensorError> {
        lock_health(&self.health).state = SensorState::Healthy;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), SensorError> {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
        lock_health(&self.health).state = SensorState::Stopped;
        Ok(())
    }

    fn health(&self) -> SensorHealth {
        let h = lock_health(&self.health);
        SensorHealth {
            name: self.name().to_string(),
            state: h.state,
            events_emitted_total: h.events_emitted_total,
            events_dropped_total: h.events_dropped_total,
            last_error: h.last_error.clone(),
            last_event_at: h.last_event_at,
            capability_flags: h.capability_flags.clone(),
            p99_emit_latency_us: 0,
        }
    }

    fn metrics(&self) -> SensorMetrics {
        let h = lock_health(&self.health);
        SensorMetrics {
            events_emitted_total: h.events_emitted_total,
            events_dropped_total: h.events_dropped_total,
        }
    }
}

async fn emit(
    output: &tokio::sync::mpsc::Sender<RawEvent>,
    raw: osiris_sensor_api::SystemdEventRaw,
    health: &Mutex<HealthState>,
) {
    let timestamp = raw.timestamp_ns;
    if output.send(RawEvent::Systemd(raw)).await.is_ok() {
        let mut h = lock_health(health);
        h.events_emitted_total += 1;
        h.last_event_at = Some(timestamp);
        h.state = SensorState::Healthy;
    } else {
        lock_health(health).events_dropped_total += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::{RawEvent, Sensor, SensorContext, SensorState, SystemdOperation};
    use std::io::Write;
    use tokio::sync::mpsc;

    const SERVICE_START: &str = r#"type=SERVICE_START msg=audit(1690000000.123:501): pid=1 uid=0 auid=1000 ses=3 subj=unconfined msg='unit=backdoor.service comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'"#;

    #[tokio::test]
    async fn reports_unsupported_when_the_audit_log_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut sensor = SystemdSensor::new(dir.path().join("missing.log"));
        let caps = sensor.capabilities();
        assert!(!caps.supported());
        let (tx, _rx) = mpsc::channel(16);
        let result = sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn emits_a_systemd_event_from_a_tailed_service_start_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();

        let mut sensor =
            SystemdSensor::new(&path).with_poll_interval(Duration::from_millis(20));
        let (tx, mut rx) = mpsc::channel(16);
        let cancellation = CancellationToken::new();
        sensor
            .initialize(SensorContext::new(tx, cancellation.clone()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "{SERVICE_START}").unwrap();
        file.flush().unwrap();

        let received = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");
        match received {
            RawEvent::Systemd(raw) => {
                assert_eq!(raw.operation, SystemdOperation::Start);
                assert_eq!(raw.unit_name, "backdoor.service");
                assert_eq!(raw.session_id.as_deref(), Some("3"));
            }
            other => panic!("expected RawEvent::Systemd, got {other:?}"),
        }

        sensor.stop().await.unwrap();
        assert_eq!(sensor.health().events_emitted_total, 1);
        assert_eq!(sensor.health().state, SensorState::Stopped);
    }

    #[tokio::test]
    async fn emits_nothing_for_a_log_containing_only_other_subsystems_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(
            &path,
            "type=USER_LOGIN msg=audit(1690000000.123:456): pid=1200 uid=0 msg='res=success'\n",
        )
        .unwrap();

        let mut sensor =
            SystemdSensor::new(&path).with_poll_interval(Duration::from_millis(20));
        let (tx, mut rx) = mpsc::channel(16);
        let cancellation = CancellationToken::new();
        sensor
            .initialize(SensorContext::new(tx, cancellation.clone()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        let received = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(received.is_err(), "must emit nothing for records it does not own");
        sensor.stop().await.unwrap();
        assert_eq!(sensor.health().events_emitted_total, 0);
    }
}
```

- [ ] **Step 6: Wire up `lib.rs`**

Write `crates/osiris-sensors/systemd/src/lib.rs`:

```rust
pub mod audit_record;
pub mod sensor;

pub use sensor::SystemdSensor;
```

- [ ] **Step 7: Run the full crate test suite**

Run: `cargo test -p osiris-sensors-systemd`
Expected: PASS — all parser tests (Step 3) and sensor tests (Step 5).

- [ ] **Step 8: Re-run the dependency-graph check**

Run: `bash tools/check-dep-graph.sh`
Expected: `Dependency-graph check PASSED` — `osiris-sensors-systemd` now has real dependencies (`osiris-sensor-api`, `osiris-fileutil`, `tokio`, etc.) and the Step 2 check confirms none of them are `osiris-server`/`osiris-api`.

- [ ] **Step 9: Run the full workspace build**

Run: `cargo build --workspace --all-targets`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add Cargo.toml Cargo.lock tools/check-dep-graph.sh crates/osiris-sensors/systemd
git commit -m "feat(sensors): osiris-sensors-systemd, the audit-backed Systemd sensor"
```

## Task 6: `osiris-sensors-persistence` — the periodic scan-and-diff Persistence Monitor

**Files:**
- Create: `crates/osiris-sensors/persistence/Cargo.toml`
- Create: `crates/osiris-sensors/persistence/src/lib.rs`
- Create: `crates/osiris-sensors/persistence/src/target.rs`
- Create: `crates/osiris-sensors/persistence/src/poller.rs`
- Create: `crates/osiris-sensors/persistence/src/sensor.rs`
- Modify: `tools/check-dep-graph.sh` (add the forbidden-dependency check)

**Interfaces:**
- Consumes: Task 3's `PersistenceEventRaw`/`PersistenceOperation`/`PersistenceCheckpointKind`/`RawEventSource`.
- Produces: `osiris_sensors_persistence::{PersistenceWatchTarget, PersistenceWatchKind, PersistenceSensor}`. `PersistenceSensor::new(watch_targets: Vec<PersistenceWatchTarget>) -> Self`, `.with_poll_interval(Duration) -> Self`, implementing `Sensor`. Task 8 wires this into `osiris-agent` and defines `PersistenceWatchTarget`'s `serde::Deserialize` shape for `agent.yaml`.

**Before writing any code**, re-read `crates/osiris-sensors/net/src/poller.rs` and `crates/osiris-sensors/net/src/sensor.rs` in full (already read once while planning this task) — this is the first *polling* (not audit-tailing) sensor since Phase 3's Network sensor, and this task's `sensor.rs` mirrors `NetworkSensor`'s shape (a spawned poll loop with `tokio::select!` sleep/cancellation), not `IdentitySensor`'s `LineTailer` shape.

- [ ] **Step 1: Add the crate manifest**

(The workspace-root `Cargo.toml` `members` array was already extended for both new sensor crates in Task 5, Step 1 — nothing to add there.)

Create `crates/osiris-sensors/persistence/Cargo.toml`:

```toml
[package]
name = "osiris-sensors-persistence"
version.workspace = true
edition.workspace = true

[dependencies]
tokio = { workspace = true }
tokio-util = { workspace = true }
async-trait = { workspace = true }
serde = { workspace = true }
sha2 = { workspace = true }
osiris-sensor-api = { path = "../../osiris-sensor-api" }

[dev-dependencies]
tempfile = { workspace = true }
```

In `tools/check-dep-graph.sh`, add immediately after the `check_forbidden osiris-sensors-systemd osiris-server osiris-api` line added in Task 5:

```bash
check_forbidden osiris-sensors-persistence osiris-server osiris-api
```

- [ ] **Step 2: Write the failing target-classification tests**

Create `crates/osiris-sensors/persistence/src/target.rs`:

```rust
use std::path::PathBuf;

use osiris_sensor_api::PersistenceCheckpointKind;
use serde::Deserialize;

/// One config-declared thing to watch (plan Global Constraint #4): a path
/// (file or directory) and the checkpoint kind it holds. Explicit,
/// never inferred from the path string itself — an operator who points
/// `kind: cron` at the wrong directory gets exactly what they configured.
#[derive(Debug, Clone, Deserialize)]
pub struct PersistenceWatchTarget {
    pub path: String,
    pub kind: PersistenceWatchKind,
}

/// The declared kind of a watch target. `SystemdUnitDir` is the one kind
/// this crate further splits *within* itself, by file extension, into
/// `PersistenceCheckpointKind::SystemdUnit`/`SystemdTimer` — every other
/// kind maps 1:1 onto one `PersistenceCheckpointKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceWatchKind {
    SystemdUnitDir,
    Cron,
    ShellProfile,
    LdPreload,
    Sudoers,
}

/// Classifies one discovered file against the watch target that found it.
/// For `SystemdUnitDir`, only `.service` and `.timer` files are recognized
/// — anything else in that directory (`.socket`, `.mount`, `.path`, etc.)
/// returns `None` and the caller skips it silently (plan Global Constraint
/// #4: a documented, deliberate drop, not a guess).
pub fn checkpoint_kind_for(target_kind: PersistenceWatchKind, path: &std::path::Path) -> Option<PersistenceCheckpointKind> {
    match target_kind {
        PersistenceWatchKind::SystemdUnitDir => match path.extension().and_then(|e| e.to_str()) {
            Some("service") => Some(PersistenceCheckpointKind::SystemdUnit),
            Some("timer") => Some(PersistenceCheckpointKind::SystemdTimer),
            _ => None,
        },
        PersistenceWatchKind::Cron => Some(PersistenceCheckpointKind::Cron),
        PersistenceWatchKind::ShellProfile => Some(PersistenceCheckpointKind::ShellProfile),
        PersistenceWatchKind::LdPreload => Some(PersistenceCheckpointKind::LdPreload),
        PersistenceWatchKind::Sudoers => Some(PersistenceCheckpointKind::Sudoers),
    }
}

/// Lists the candidate files a target actually covers right now: every
/// immediate entry (non-recursive — plan-scoped minimalism, matching this
/// codebase's "MVP scope, not the eventual design" style elsewhere) if
/// `target.path` is a directory, or the single path itself if it's a file
/// (`/etc/crontab`, `/etc/ld.so.preload` are watched as one file each, not
/// a directory). A target whose path does not exist yet yields no
/// candidates — not an error, since a not-yet-created persistence
/// checkpoint directory is a completely ordinary state, not a fault.
pub fn candidate_paths(target: &PersistenceWatchTarget) -> Vec<PathBuf> {
    let path = PathBuf::from(&target.path);
    if path.is_dir() {
        std::fs::read_dir(&path)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|p| p.is_file())
            .collect()
    } else if path.is_file() {
        vec![path]
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_file_in_a_unit_dir_classifies_as_systemd_unit() {
        assert_eq!(
            checkpoint_kind_for(
                PersistenceWatchKind::SystemdUnitDir,
                std::path::Path::new("/etc/systemd/system/backdoor.service")
            ),
            Some(PersistenceCheckpointKind::SystemdUnit)
        );
    }

    #[test]
    fn a_timer_file_in_a_unit_dir_classifies_as_systemd_timer() {
        assert_eq!(
            checkpoint_kind_for(
                PersistenceWatchKind::SystemdUnitDir,
                std::path::Path::new("/etc/systemd/system/backdoor.timer")
            ),
            Some(PersistenceCheckpointKind::SystemdTimer)
        );
    }

    #[test]
    fn a_socket_file_in_a_unit_dir_is_silently_skipped() {
        assert_eq!(
            checkpoint_kind_for(
                PersistenceWatchKind::SystemdUnitDir,
                std::path::Path::new("/etc/systemd/system/backdoor.socket")
            ),
            None
        );
    }

    #[test]
    fn a_cron_target_classifies_everything_as_cron_regardless_of_extension() {
        assert_eq!(
            checkpoint_kind_for(
                PersistenceWatchKind::Cron,
                std::path::Path::new("/etc/cron.d/anything.txt")
            ),
            Some(PersistenceCheckpointKind::Cron)
        );
    }

    #[test]
    fn candidate_paths_lists_immediate_files_in_a_directory_target() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.service"), "x").unwrap();
        std::fs::write(dir.path().join("b.timer"), "y").unwrap();
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        let target = PersistenceWatchTarget {
            path: dir.path().to_string_lossy().to_string(),
            kind: PersistenceWatchKind::SystemdUnitDir,
        };
        let mut found: Vec<_> = candidate_paths(&target)
            .into_iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        found.sort();
        assert_eq!(found, vec!["a.service".to_string(), "b.timer".to_string()]);
    }

    #[test]
    fn candidate_paths_treats_a_single_file_target_as_one_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ld.so.preload");
        std::fs::write(&file, "x").unwrap();
        let target = PersistenceWatchTarget {
            path: file.to_string_lossy().to_string(),
            kind: PersistenceWatchKind::LdPreload,
        };
        assert_eq!(candidate_paths(&target).len(), 1);
    }

    #[test]
    fn candidate_paths_is_empty_for_a_target_that_does_not_exist_yet() {
        let target = PersistenceWatchTarget {
            path: "/does/not/exist".to_string(),
            kind: PersistenceWatchKind::Cron,
        };
        assert!(candidate_paths(&target).is_empty());
    }
}
```

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test -p osiris-sensors-persistence`
Expected: PASS — this module is new and self-contained.

- [ ] **Step 4: Write the failing poller tests**

Create `crates/osiris-sensors/persistence/src/poller.rs`:

```rust
use std::collections::HashMap;
use std::path::PathBuf;

use osiris_sensor_api::{PersistenceEventRaw, PersistenceOperation, RawEventSource};
use sha2::{Digest, Sha256};

use crate::target::{candidate_paths, checkpoint_kind_for, PersistenceWatchTarget};

#[derive(Clone)]
struct SeenFile {
    hash: String,
    size: u64,
}

/// Scans every configured `PersistenceWatchTarget` and diffs the result
/// against the previous tick (plan Global Constraint #1: this is the one
/// mechanism that produces BOTH Systemd unit-file-lifecycle events and
/// generic Persistence events — the classification into which is which
/// happens per-file via `checkpoint_kind_for`, not by two separate
/// scanners).
///
/// KNOWN, DELIBERATE BEHAVIOR (plan Global Constraint #8 — NOT the same
/// choice `NetworkPoller` made, and that is intentional): the very first
/// `poll()` call after construction seeds `previous` from whatever it finds
/// and emits NOTHING for it. Only a change observed between tick N and
/// tick N+1, once a first scan has already completed, is ever reported.
pub struct PersistencePoller {
    targets: Vec<PersistenceWatchTarget>,
    previous: HashMap<PathBuf, SeenFile>,
    first_scan_done: bool,
}

impl PersistencePoller {
    pub fn new(targets: Vec<PersistenceWatchTarget>) -> Self {
        Self {
            targets,
            previous: HashMap::new(),
            first_scan_done: false,
        }
    }

    /// One scan tick. Returns every Created/Modified/Removed event since
    /// the previous tick — or, on the very first call, updates internal
    /// state and returns an empty `Vec` unconditionally (Global Constraint
    /// #8).
    pub fn poll(&mut self, now_ns: u64) -> Vec<PersistenceEventRaw> {
        let mut current: HashMap<PathBuf, (SeenFile, osiris_sensor_api::PersistenceCheckpointKind)> =
            HashMap::new();
        for target in &self.targets {
            for path in candidate_paths(target) {
                let Some(kind) = checkpoint_kind_for(target.kind, &path) else {
                    continue;
                };
                let Ok(bytes) = std::fs::read(&path) else {
                    continue;
                };
                let hash = format!("{:x}", Sha256::digest(&bytes));
                current.insert(
                    path,
                    (
                        SeenFile {
                            hash,
                            size: bytes.len() as u64,
                        },
                        kind,
                    ),
                );
            }
        }

        if !self.first_scan_done {
            self.first_scan_done = true;
            self.previous = current.into_iter().map(|(p, (f, _))| (p, f)).collect();
            return vec![];
        }

        let mut events = Vec::new();
        for (path, (seen, kind)) in &current {
            match self.previous.get(path) {
                None => events.push(make_event(
                    PersistenceOperation::Created,
                    *kind,
                    path,
                    Some(seen.clone()),
                    now_ns,
                )),
                Some(prior) if prior.hash != seen.hash => events.push(make_event(
                    PersistenceOperation::Modified,
                    *kind,
                    path,
                    Some(seen.clone()),
                    now_ns,
                )),
                Some(_) => {}
            }
        }
        for path in self.previous.keys() {
            if !current.contains_key(path) {
                // The removed file's checkpoint kind is no longer
                // discoverable from `current` (it's gone) — but every
                // target this poller was ever configured with is still in
                // `self.targets`, so re-derive it the same way `poll`
                // itself does, from whichever target's directory the path
                // lived under.
                if let Some(kind) = self.targets.iter().find_map(|t| {
                    if PathBuf::from(&t.path) == *path || path.starts_with(&t.path) {
                        checkpoint_kind_for(t.kind, path)
                    } else {
                        None
                    }
                }) {
                    events.push(make_event(
                        PersistenceOperation::Removed,
                        kind,
                        path,
                        None,
                        now_ns,
                    ));
                }
            }
        }

        self.previous = current.into_iter().map(|(p, (f, _))| (p, f)).collect();
        events
    }
}

fn make_event(
    operation: PersistenceOperation,
    checkpoint_kind: osiris_sensor_api::PersistenceCheckpointKind,
    path: &std::path::Path,
    seen: Option<SeenFile>,
    now_ns: u64,
) -> PersistenceEventRaw {
    PersistenceEventRaw {
        operation,
        checkpoint_kind,
        path: path.to_string_lossy().to_string(),
        content_hash: seen.as_ref().map(|s| s.hash.clone()),
        size: seen.as_ref().map(|s| s.size),
        timestamp_ns: now_ns,
        source: RawEventSource::Procfs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::PersistenceWatchKind;

    fn unit_dir_target(path: &std::path::Path) -> PersistenceWatchTarget {
        PersistenceWatchTarget {
            path: path.to_string_lossy().to_string(),
            kind: PersistenceWatchKind::SystemdUnitDir,
        }
    }

    #[test]
    fn the_first_poll_seeds_a_baseline_and_emits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("preexisting.service"), "x").unwrap();
        let mut poller = PersistencePoller::new(vec![unit_dir_target(dir.path())]);
        assert!(poller.poll(1_000).is_empty());
    }

    #[test]
    fn a_file_created_after_the_first_scan_emits_created() {
        let dir = tempfile::tempdir().unwrap();
        let mut poller = PersistencePoller::new(vec![unit_dir_target(dir.path())]);
        assert!(poller.poll(1_000).is_empty());

        std::fs::write(dir.path().join("backdoor.service"), "malicious").unwrap();
        let events = poller.poll(2_000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, PersistenceOperation::Created);
        assert_eq!(
            events[0].checkpoint_kind,
            osiris_sensor_api::PersistenceCheckpointKind::SystemdUnit
        );
        assert!(events[0].path.ends_with("backdoor.service"));
        assert!(events[0].content_hash.is_some());
    }

    #[test]
    fn a_file_whose_content_changes_emits_modified_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("existing.service");
        std::fs::write(&file, "v1").unwrap();
        let mut poller = PersistencePoller::new(vec![unit_dir_target(dir.path())]);
        assert!(poller.poll(1_000).is_empty());

        std::fs::write(&file, "v2 - changed").unwrap();
        let events = poller.poll(2_000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, PersistenceOperation::Modified);
    }

    #[test]
    fn a_file_that_disappears_emits_removed_with_no_hash() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("temporary.service");
        std::fs::write(&file, "x").unwrap();
        let mut poller = PersistencePoller::new(vec![unit_dir_target(dir.path())]);
        assert!(poller.poll(1_000).is_empty());

        std::fs::remove_file(&file).unwrap();
        let events = poller.poll(2_000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, PersistenceOperation::Removed);
        assert!(events[0].content_hash.is_none());
        assert!(events[0].size.is_none());
    }

    #[test]
    fn an_unchanged_file_emits_nothing_on_the_second_poll() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stable.service"), "same").unwrap();
        let mut poller = PersistencePoller::new(vec![unit_dir_target(dir.path())]);
        assert!(poller.poll(1_000).is_empty());
        assert!(poller.poll(2_000).is_empty());
    }

    /// A `.socket` file in a unit dir is never a candidate at all (plan
    /// Global Constraint #4), so it must never surface as any kind of
    /// event, even though the real filesystem entry exists throughout.
    #[test]
    fn an_unrecognized_extension_in_a_unit_dir_is_never_reported() {
        let dir = tempfile::tempdir().unwrap();
        let mut poller = PersistencePoller::new(vec![unit_dir_target(dir.path())]);
        assert!(poller.poll(1_000).is_empty());
        std::fs::write(dir.path().join("ignored.socket"), "x").unwrap();
        assert!(poller.poll(2_000).is_empty());
    }
}
```

- [ ] **Step 5: Run the poller tests**

Run: `cargo test -p osiris-sensors-persistence`
Expected: PASS.

- [ ] **Step 6: Write the sensor**

Create `crates/osiris-sensors/persistence/src/sensor.rs`, mirroring `osiris-sensors-net`'s `sensor.rs` structure (health state, `always_available` capability gated on "at least one configured target's path currently exists", a spawned poll loop calling `PersistencePoller::poll` on a `tokio::select!`/sleep cadence):

```rust
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use osiris_sensor_api::{
    RawEvent, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth,
    SensorMetrics, SensorState,
};
use tokio_util::sync::CancellationToken;

use crate::poller::PersistencePoller;
use crate::target::PersistenceWatchTarget;

struct HealthState {
    state: SensorState,
    events_emitted_total: u64,
    events_dropped_total: u64,
    last_error: Option<String>,
    last_event_at: Option<u64>,
    capability_flags: Vec<String>,
}

impl Default for HealthState {
    fn default() -> Self {
        Self {
            state: SensorState::Starting,
            events_emitted_total: 0,
            events_dropped_total: 0,
            last_error: None,
            last_event_at: None,
            capability_flags: vec![],
        }
    }
}

fn lock_health(health: &Mutex<HealthState>) -> MutexGuard<'_, HealthState> {
    health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The Persistence sensor (ARCHITECTURE.md §4.3's Persistence row), this
/// phase's scope: the periodic-scan-only fallback backend (plan Global
/// Constraint #1) — fanotify is deferred to real-Linux validation, matching
/// every other phase's fallback-first ruling. Also owns Systemd's
/// unit-*file*-lifecycle taxonomy events (`SERVICE_CREATE`/`MODIFY`/
/// `DELETE`, `TIMER_CREATE`/`MODIFY`) per plan Global Constraint #1's
/// scan-and-diff-is-one-mechanism ruling.
pub struct PersistenceSensor {
    watch_targets: Vec<PersistenceWatchTarget>,
    poll_interval: Duration,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
}

impl PersistenceSensor {
    pub fn new(watch_targets: Vec<PersistenceWatchTarget>) -> Self {
        Self {
            watch_targets,
            poll_interval: Duration::from_secs(30),
            cancellation: None,
            task_handle: None,
            health: Arc::new(Mutex::new(HealthState::default())),
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    fn any_target_exists(&self) -> bool {
        self.watch_targets
            .iter()
            .any(|t| std::path::Path::new(&t.path).exists())
    }
}

#[async_trait]
impl Sensor for PersistenceSensor {
    fn name(&self) -> &'static str {
        "persistence"
    }

    fn capabilities(&self) -> SensorCapabilities {
        if !self.watch_targets.is_empty() && self.any_target_exists() {
            SensorCapabilities {
                ebpf: false,
                audit_fallback: false,
                always_available: true,
                unsupported_reason: None,
            }
        } else {
            SensorCapabilities {
                ebpf: false,
                audit_fallback: false,
                always_available: false,
                unsupported_reason: Some(
                    "no configured persistence_watch_paths target currently exists".to_string(),
                ),
            }
        }
    }

    async fn initialize(&mut self, ctx: SensorContext) -> Result<(), SensorError> {
        self.cancellation = Some(ctx.cancellation.clone());
        lock_health(&self.health).state = SensorState::Starting;

        let caps = self.capabilities();
        if !caps.supported() {
            let reason = caps.unsupported_reason.clone().unwrap_or_default();
            lock_health(&self.health).last_error = Some(reason.clone());
            return Err(SensorError::Unsupported(reason));
        }
        lock_health(&self.health).capability_flags = vec!["always_available".to_string()];

        let targets = self.watch_targets.clone();
        let poll_interval = self.poll_interval;
        let output = ctx.output;
        let cancellation = ctx.cancellation;
        let health = self.health.clone();

        let handle = tokio::spawn(async move {
            let mut poller = PersistencePoller::new(targets);
            loop {
                if cancellation.is_cancelled() {
                    lock_health(&health).state = SensorState::Stopped;
                    return;
                }
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                for raw in poller.poll(now_ns) {
                    emit(&output, raw, &health).await;
                }
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {}
                    _ = cancellation.cancelled() => {
                        lock_health(&health).state = SensorState::Stopped;
                        return;
                    }
                }
            }
        });
        self.task_handle = Some(handle);
        Ok(())
    }

    async fn start(&mut self) -> Result<(), SensorError> {
        lock_health(&self.health).state = SensorState::Healthy;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), SensorError> {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
        lock_health(&self.health).state = SensorState::Stopped;
        Ok(())
    }

    fn health(&self) -> SensorHealth {
        let h = lock_health(&self.health);
        SensorHealth {
            name: self.name().to_string(),
            state: h.state,
            events_emitted_total: h.events_emitted_total,
            events_dropped_total: h.events_dropped_total,
            last_error: h.last_error.clone(),
            last_event_at: h.last_event_at,
            capability_flags: h.capability_flags.clone(),
            p99_emit_latency_us: 0,
        }
    }

    fn metrics(&self) -> SensorMetrics {
        let h = lock_health(&self.health);
        SensorMetrics {
            events_emitted_total: h.events_emitted_total,
            events_dropped_total: h.events_dropped_total,
        }
    }
}

async fn emit(
    output: &tokio::sync::mpsc::Sender<RawEvent>,
    raw: osiris_sensor_api::PersistenceEventRaw,
    health: &Mutex<HealthState>,
) {
    let timestamp = raw.timestamp_ns;
    if output.send(RawEvent::Persistence(raw)).await.is_ok() {
        let mut h = lock_health(health);
        h.events_emitted_total += 1;
        h.last_event_at = Some(timestamp);
        h.state = SensorState::Healthy;
    } else {
        lock_health(health).events_dropped_total += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::PersistenceWatchKind;
    use osiris_sensor_api::{PersistenceOperation, RawEvent, Sensor, SensorContext, SensorState};

    fn unit_dir_target(path: &std::path::Path) -> PersistenceWatchTarget {
        PersistenceWatchTarget {
            path: path.to_string_lossy().to_string(),
            kind: PersistenceWatchKind::SystemdUnitDir,
        }
    }

    #[tokio::test]
    async fn reports_unsupported_when_no_target_path_exists() {
        let mut sensor = PersistenceSensor::new(vec![PersistenceWatchTarget {
            path: "/does/not/exist".to_string(),
            kind: PersistenceWatchKind::Cron,
        }]);
        let caps = sensor.capabilities();
        assert!(!caps.supported());
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let result = sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn reports_unsupported_when_no_targets_are_configured_at_all() {
        let mut sensor = PersistenceSensor::new(vec![]);
        assert!(!sensor.capabilities().supported());
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        assert!(sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn emits_a_persistence_event_for_a_file_created_after_startup() {
        let dir = tempfile::tempdir().unwrap();
        let mut sensor = PersistenceSensor::new(vec![unit_dir_target(dir.path())])
            .with_poll_interval(Duration::from_millis(30));
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let cancellation = CancellationToken::new();
        sensor
            .initialize(SensorContext::new(tx, cancellation.clone()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        // Give the sensor's first (baseline-seeding) tick time to run
        // before creating the file, so the create is genuinely observed as
        // a change, not folded into the silent first scan.
        tokio::time::sleep(Duration::from_millis(60)).await;
        std::fs::write(dir.path().join("backdoor.service"), "malicious").unwrap();

        let received = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");
        match received {
            RawEvent::Persistence(raw) => {
                assert_eq!(raw.operation, PersistenceOperation::Created);
                assert!(raw.path.ends_with("backdoor.service"));
            }
            other => panic!("expected RawEvent::Persistence, got {other:?}"),
        }
        sensor.stop().await.unwrap();
    }
}
```

- [ ] **Step 7: Wire up `lib.rs`**

Write `crates/osiris-sensors/persistence/src/lib.rs`:

```rust
pub mod poller;
pub mod sensor;
pub mod target;

pub use sensor::PersistenceSensor;
pub use target::{PersistenceWatchKind, PersistenceWatchTarget};
```

- [ ] **Step 8: Run the full crate test suite**

Run: `cargo test -p osiris-sensors-persistence`
Expected: PASS — all target, poller, and sensor tests.

- [ ] **Step 9: Re-run the dependency-graph check and full workspace build**

Run: `bash tools/check-dep-graph.sh`
Expected: `Dependency-graph check PASSED`.

Run: `cargo build --workspace --all-targets`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add tools/check-dep-graph.sh crates/osiris-sensors/persistence Cargo.lock
git commit -m "feat(sensors): osiris-sensors-persistence, the scan-and-diff Persistence Monitor"
```

## Task 7: `osiris-storage` + `osiris-storage-sqlite` — `unit_name` query filter

**Files:**
- Modify: `crates/osiris-storage/src/plan.rs`
- Modify: `crates/osiris-storage-sqlite/src/sqlite_storage.rs`

**Interfaces:**
- Consumes: `CanonicalEvent.service: Option<ServiceRef>`, populated by Task 4 for every Systemd-category event (both from Task 5's audit sensor and Task 6's monitor's unit-file results).
- Produces: `osiris_storage::QueryPlan.unit_name: Option<String>` — exact match on `service.unit_name`. Task 10's `systemd_story_handler` uses it.
- **No `Storage` trait change** — identical reasoning to every prior phase's additive `QueryPlan` field: a plain struct with `Default`, one new nullable column, breaks no implementor.

**Before writing any code**, open `crates/osiris-storage-sqlite/src/sqlite_storage.rs` and confirm the three mechanisms this task extends are still shaped as Phase 4a's Task 4 left them: the `CREATE TABLE IF NOT EXISTS events (...)` fresh-DB column list; the `for (column, ddl) in [...]` migration loop; the `execute_batch` that creates indexes after it. All three must be edited together.

- [ ] **Step 1: Write the failing `QueryPlan` test**

Append to `crates/osiris-storage/src/plan.rs`'s `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn new_query_plan_defaults_unit_name_to_none_too() {
        let plan = QueryPlan::new();
        assert!(plan.unit_name.is_none());
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p osiris-storage`
Expected: FAIL to compile — `no field unit_name on type QueryPlan`.

- [ ] **Step 3: Add the field**

In `crates/osiris-storage/src/plan.rs`, insert into `QueryPlan` immediately after the existing `user_uid` field:

```rust
    /// Exact-match on `service.unit_name`. Covers both this phase's
    /// Systemd runtime-lifecycle events (`SERVICE_START`/`STOP`) and its
    /// unit-*file*-lifecycle events (`SERVICE_CREATE`/`MODIFY`/`DELETE`,
    /// `TIMER_CREATE`/`MODIFY`) — Task 4's Normalize populates
    /// `service.unit_name` identically for both, so one filter serves the
    /// whole unit's history regardless of which sensor observed which part
    /// of it.
    pub unit_name: Option<String>,
```

Run: `cargo test -p osiris-storage`
Expected: PASS.

- [ ] **Step 4: Write the failing storage tests**

Append to `crates/osiris-storage-sqlite/src/sqlite_storage.rs`'s `#[cfg(test)] mod tests`. Read the module's existing `sample_event`/`identity_event`/`open_test_storage` helpers first — this reuses `identity_event`'s shape, extended with a `service` field.

```rust
    fn systemd_event(unit_name: &str, timestamp: u64) -> CanonicalEvent {
        let mut event = sample_event(500, timestamp);
        event.event_type = osiris_schema::EventType::ServiceStart;
        event.category = osiris_schema::Category::Systemd;
        event.service = Some(osiris_schema::ServiceRef {
            unit_name: unit_name.to_string(),
            unit_type: "service".to_string(),
            action: "start".to_string(),
        });
        event
    }

    #[test]
    fn query_filters_by_unit_name() {
        let storage = open_test_storage();
        let backdoor = systemd_event("backdoor.service", 1000);
        let mut backdoor_stop = systemd_event("backdoor.service", 2000);
        backdoor_stop.event_type = osiris_schema::EventType::ServiceStop;
        let sshd = systemd_event("sshd.service", 3000);
        // An event with no service at all must never match any unit_name
        // filter — NULL never equals a string in SQL, same discipline as
        // Phase 4a's uid-0-vs-NULL distinction.
        let unrelated = sample_event(900, 4000);
        storage
            .batch_write(&[
                backdoor.clone(),
                backdoor_stop.clone(),
                sshd.clone(),
                unrelated,
            ])
            .unwrap();

        let mut plan = QueryPlan::new();
        plan.unit_name = Some("backdoor.service".to_string());
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 2);
        let ids: Vec<_> = results.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&backdoor.event_id));
        assert!(ids.contains(&backdoor_stop.event_id));
        assert!(!ids.contains(&sshd.event_id));
    }

    /// Non-destructive/idempotent migration proof, matching every prior
    /// phase's precedent exactly.
    #[test]
    fn migrates_a_pre_phase_4b_database_without_data_loss() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let pre_phase_4b_event = sample_event(300, 1000);
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE events (
                    event_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    process_key TEXT,
                    parent_process_key TEXT,
                    file_path TEXT,
                    file_inode INTEGER,
                    file_device_id INTEGER,
                    network_src_ip TEXT,
                    network_dst_ip TEXT,
                    dns_domain TEXT,
                    session_id TEXT,
                    user_uid INTEGER,
                    raw_json TEXT NOT NULL
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO events (event_id, host_id, timestamp, event_type, raw_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    pre_phase_4b_event.event_id.to_string(),
                    pre_phase_4b_event.host_id.to_string(),
                    pre_phase_4b_event.timestamp as i64,
                    "PROCESS_EXEC",
                    serde_json::to_string(&pre_phase_4b_event).unwrap(),
                ],
            )
            .unwrap();
        }

        let reopened = SqliteStorage::open(&db_path).unwrap();
        assert_eq!(
            reopened.query(&QueryPlan::new()).unwrap().len(),
            1,
            "the pre-existing row must survive migration"
        );

        reopened.write(&systemd_event("backdoor.service", 2000)).unwrap();
        let mut plan = QueryPlan::new();
        plan.unit_name = Some("backdoor.service".to_string());
        assert_eq!(
            reopened.query(&plan).unwrap().len(),
            1,
            "the migrated unit_name column must exist and filter correctly"
        );

        let reopened_again = SqliteStorage::open(&db_path).unwrap();
        assert_eq!(reopened_again.query(&QueryPlan::new()).unwrap().len(), 2);
        assert_eq!(reopened_again.query(&plan).unwrap().len(), 1);
    }
```

- [ ] **Step 5: Run them to verify they fail**

Run: `cargo test -p osiris-storage-sqlite`
Expected: `no such column: unit_name` at runtime (the `QueryPlan` field already exists from Step 3, so this compiles but the SQL isn't wired yet).

- [ ] **Step 6: Add the column, the index, and the two SQL clauses**

Three coordinated edits in `crates/osiris-storage-sqlite/src/sqlite_storage.rs`.

(a) Fresh-database DDL — add to the `CREATE TABLE IF NOT EXISTS events (...)` list, immediately after `user_uid INTEGER,`:

```sql
                unit_name TEXT,
```

(b) Migration loop — append one entry to the `for (column, ddl) in [...]` array, and extend the comment block above it:

```rust
            ("unit_name", "ALTER TABLE events ADD COLUMN unit_name TEXT"),
```

Extend the existing comment block above the loop with:

```rust
        // Phase 4b adds `unit_name` the same way. As with every earlier
        // phase's columns, pre-existing rows are not backfilled — they
        // read back NULL. No database created before Phase 4b can contain
        // an event with a populated `service`, so this has no practical
        // impact.
```

Add the index to the `execute_batch` that follows the loop:

```sql
             CREATE INDEX IF NOT EXISTS idx_events_unit_name ON events(unit_name);
```

(c) `batch_write` — extract the value alongside the existing `session_id`/`user_uid` extraction, add it to the INSERT's column list, placeholder list (`?16`), and `params!`:

```rust
            let unit_name = event.service.as_ref().map(|s| s.unit_name.clone());
```

INSERT becomes (column list and placeholders both extended by one, `raw_json` still last):

```rust
                    "INSERT OR IGNORE INTO events (event_id, host_id, timestamp, event_type, process_key, parent_process_key, file_path, file_inode, file_device_id, network_src_ip, network_dst_ip, dns_domain, session_id, user_uid, unit_name, raw_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
```

with `unit_name,` inserted into `params![...]` immediately before `raw_json`.

(d) `query` — add the clause after the existing `user_uid` clause and before `since`/`until`:

```rust
        if let Some(unit_name) = &plan.unit_name {
            sql.push_str(" AND unit_name = ?");
            sql_params.push(Box::new(unit_name.clone()));
        }
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p osiris-storage -p osiris-storage-sqlite`
Expected: PASS.

- [ ] **Step 8: Run the full workspace build**

Run: `cargo build --workspace --all-targets`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/osiris-storage/src/plan.rs crates/osiris-storage-sqlite/src/sqlite_storage.rs
git commit -m "feat(storage): unit_name query filter"
```

## Task 8: `generator` + `osiris-agent` — the persistence-via-systemd-service scenario and sensor wiring

**Files:**
- Modify: `generator/src/scenarios.rs`
- Modify: `generator/src/lib.rs`
- Modify: `crates/osiris-agent/src/config.rs`
- Modify: `crates/osiris-agent/src/agent.rs`
- Modify: `crates/osiris-agent/Cargo.toml`

**Interfaces:**
- Consumes: Task 3's raw types; Task 5's `SystemdSensor`; Task 6's `PersistenceSensor`/`PersistenceWatchTarget`/`PersistenceWatchKind`.
- Produces:
  - `osiris_generator::scenarios::persistence_via_systemd_service_scenario(base_ts_ns: u64) -> Vec<RawEvent>` plus constants `BACKDOOR_UNIT_NAME`, `BACKDOOR_UNIT_PATH`.
  - `AgentConfig.systemd_audit_log_path: Option<String>`, `AgentConfig.persistence_watch_paths: Vec<PersistenceWatchTarget>` (both `#[serde(default)]`, so every existing Phase 1-4a `agent.yaml` still loads).
  - `synthetic_scenario: Some("persistence_via_systemd_service")` selects the new scenario.
  - Task 11's e2e test drives the Agent with exactly this config.

**Before writing any code**, read `generator/src/scenarios.rs`'s `ssh_sudo_escalation_scenario` and its `exec` helper end to end (already done while planning this task), and `crates/osiris-agent/src/agent.rs`'s `Agent::start` to confirm `candidate_sensors` construction and the `match config.synthetic_scenario.as_deref()` dispatch are still shaped as this task assumes.

- [ ] **Step 1: Write the failing scenario tests**

Append to `generator/src/scenarios.rs`'s `#[cfg(test)] mod tests`:

```rust
    fn systemd_raw_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::SystemdEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::Systemd(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    fn persistence_raw_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::PersistenceEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::Persistence(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    /// The Phase 4b flagship trace: an already-escalated attacker (this
    /// scenario opens with the same SSH-login-then-sudo shape
    /// `ssh_sudo_escalation_scenario` established) installs a backdoor
    /// systemd service and starts it — the identity->process->privilege
    /// chain now continuing into PERSISTENCE and SYSTEMD, the two
    /// categories this phase adds. Nine events across five categories,
    /// under one session id once the Enrich stage's `SessionResolver` (and
    /// Task 1's fix) has propagated it.
    #[test]
    fn persistence_via_systemd_service_scenario_spans_all_five_categories_under_one_session() {
        let scenario = persistence_via_systemd_service_scenario(1_000_000_000);
        assert_eq!(scenario.len(), 9);

        assert_eq!(exec_events(&scenario).len(), 3, "sshd, bash, sudo");

        let identity = identity_raw_events(&scenario);
        assert_eq!(identity.len(), 2, "one login, one logout");
        assert_eq!(identity[0].session_id, SSH_SESSION_ID);

        let privilege = privilege_raw_events(&scenario);
        assert_eq!(privilege.len(), 2, "one sudo invocation, one uid change");
        assert_eq!(privilege[1].target_uid, Some(0), "escalation to root");

        let persistence = persistence_raw_events(&scenario);
        assert_eq!(persistence.len(), 1);
        assert_eq!(persistence[0].path, BACKDOOR_UNIT_PATH);
        assert_eq!(
            persistence[0].checkpoint_kind,
            osiris_sensor_api::PersistenceCheckpointKind::SystemdUnit
        );

        let systemd = systemd_raw_events(&scenario);
        assert_eq!(systemd.len(), 1);
        assert_eq!(systemd[0].unit_name, BACKDOOR_UNIT_NAME);
        assert_eq!(
            systemd[0].operation,
            osiris_sensor_api::SystemdOperation::Start
        );
        assert_eq!(
            systemd[0].session_id.as_deref(),
            Some(SSH_SESSION_ID),
            "the service-start record's own observed session is what makes \
             Task 9's rule expressible"
        );
        // Genuinely systemd's own pid, not the attacker's shell — plan
        // Global Constraint #3's disclosure, pinned as a test so a future
        // edit cannot casually "fix" it into pid 300 by mistake.
        assert_eq!(systemd[0].pid, 1);
    }

    /// The exec chain must form a real ancestry (Global Constraint #2 in
    /// Phase 4a's sense: the generator must produce records the real
    /// sensors could actually have produced) even though the Persistence
    /// and Systemd events themselves carry no pid the chain reaches.
    #[test]
    fn every_exec_event_descends_from_the_logins_pid() {
        let scenario = persistence_via_systemd_service_scenario(1_000_000_000);
        let execs = exec_events(&scenario);
        assert_eq!((execs[0].pid, execs[0].ppid), (100, 1), "sshd");
        assert_eq!((execs[1].pid, execs[1].ppid), (200, 100), "bash under sshd");
        assert_eq!((execs[2].pid, execs[2].ppid), (300, 200), "sudo under bash");
    }

    #[test]
    fn persistence_via_systemd_service_scenario_is_strictly_time_ordered_and_ends_with_the_logout() {
        let scenario = persistence_via_systemd_service_scenario(1_000_000_000);
        let timestamps: Vec<u64> = scenario.iter().map(RawEvent::timestamp_ns).collect();
        let mut sorted = timestamps.clone();
        sorted.sort();
        assert_eq!(timestamps, sorted);
        assert!(timestamps.windows(2).all(|w| w[0] < w[1]));
        assert!(matches!(scenario.last(), Some(RawEvent::Identity(i)) if i.operation
            == osiris_sensor_api::IdentityOperation::Logout));
    }
```

Also extend the module's existing `every_scenario_is_strictly_time_ordered` test's scenario list with `persistence_via_systemd_service_scenario(1_000_000_000)` — read that test first; it iterates a slice of scenarios, and the new one belongs in it.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p osiris-generator`
Expected: FAIL to compile — `cannot find function persistence_via_systemd_service_scenario`, `cannot find value BACKDOOR_UNIT_NAME`.

- [ ] **Step 3: Implement the scenario**

In `generator/src/scenarios.rs`, extend the `use` block:

```rust
use osiris_sensor_api::{
    DnsEventRaw, FileEventRaw, FileOperation, IdentityEventRaw, IdentityOperation,
    NetworkDirection, NetworkEventRaw, NetworkOperation, PersistenceCheckpointKind,
    PersistenceEventRaw, PersistenceOperation, PrivilegeEventRaw, PrivilegeOperation,
    ProcessExecRaw, RawEvent, RawEventSource, SystemdEventRaw, SystemdOperation,
};
```

Add the constants next to the existing scenario constants:

```rust
/// The backdoor systemd service Task 9's rule exists to catch.
pub const BACKDOOR_UNIT_NAME: &str = "backdoor.service";
pub const BACKDOOR_UNIT_PATH: &str = "/etc/systemd/system/backdoor.service";
```

Append the scenario function after `ssh_sudo_escalation_scenario`:

```rust
/// Phase 4b's flagship trace: the same SSH-login-then-sudo-escalation
/// opening `ssh_sudo_escalation_scenario` uses, now continuing into
/// PERSISTENCE and SYSTEMD instead of FILE and NETWORK — an already-root
/// attacker installs a backdoor systemd unit file (observed by Persistence
/// Monitor's periodic scan, unattributed — no pid triggered it) and starts
/// it (observed by the audit-backed Systemd sensor, whose record's own
/// `ses=` carries the SSH session id directly). Nine events spanning five
/// categories, every one of them under session id `SSH_SESSION_ID` once
/// Task 1's fixed `SessionResolver` has propagated or directly observed it.
pub fn persistence_via_systemd_service_scenario(base_ts_ns: u64) -> Vec<RawEvent> {
    vec![
        exec(100, 1, "/usr/sbin/sshd", "sshd", base_ts_ns),
        RawEvent::Identity(IdentityEventRaw {
            operation: IdentityOperation::Login,
            session_id: SSH_SESSION_ID.to_string(),
            pid: 100,
            uid: 0,
            auid: Some(1000),
            username: Some("alice".to_string()),
            terminal: Some("/dev/pts/0".to_string()),
            remote_addr: Some(SSH_REMOTE_ADDR.to_string()),
            auth_method: Some("sshd".to_string()),
            success: true,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: base_ts_ns + 1_000_000,
            audit_serial: Some(456),
            source: RawEventSource::Synthetic,
        }),
        exec(200, 100, "/bin/bash", "bash", base_ts_ns + 2_000_000),
        exec(300, 200, "/usr/bin/sudo", "sudo", base_ts_ns + 3_000_000),
        RawEvent::Privilege(PrivilegeEventRaw {
            operation: PrivilegeOperation::Sudo,
            pid: 300,
            ppid: 0,
            uid: 1000,
            gid: None,
            euid: None,
            egid: None,
            auid: Some(1000),
            session_id: Some(SSH_SESSION_ID.to_string()),
            username: None,
            target_uid: None,
            target_gid: None,
            command: Some("/usr/bin/systemctl enable --now backdoor.service".to_string()),
            success: true,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: base_ts_ns + 4_000_000,
            audit_serial: Some(469),
            source: RawEventSource::Synthetic,
        }),
        RawEvent::Privilege(PrivilegeEventRaw {
            operation: PrivilegeOperation::UidChange,
            pid: 300,
            ppid: 200,
            uid: 1000,
            gid: Some(1000),
            euid: Some(0),
            egid: Some(1000),
            auid: Some(1000),
            session_id: Some(SSH_SESSION_ID.to_string()),
            username: None,
            target_uid: Some(0),
            target_gid: None,
            command: None,
            success: true,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: base_ts_ns + 5_000_000,
            audit_serial: Some(470),
            source: RawEventSource::Synthetic,
        }),
        RawEvent::Persistence(PersistenceEventRaw {
            operation: PersistenceOperation::Created,
            checkpoint_kind: PersistenceCheckpointKind::SystemdUnit,
            path: BACKDOOR_UNIT_PATH.to_string(),
            content_hash: Some("b".repeat(64)),
            size: Some(96),
            timestamp_ns: base_ts_ns + 6_000_000,
            source: RawEventSource::Procfs,
        }),
        RawEvent::Systemd(SystemdEventRaw {
            operation: SystemdOperation::Start,
            unit_name: BACKDOOR_UNIT_NAME.to_string(),
            // Genuinely systemd's own pid on a real host (plan Global
            // Constraint #3) — never the attacker's pid 300.
            pid: 1,
            uid: 0,
            auid: Some(1000),
            session_id: Some(SSH_SESSION_ID.to_string()),
            success: true,
            exe_path: "/usr/lib/systemd/systemd".to_string(),
            comm: "systemd".to_string(),
            timestamp_ns: base_ts_ns + 7_000_000,
            audit_serial: Some(512),
            source: RawEventSource::Synthetic,
        }),
        RawEvent::Identity(IdentityEventRaw {
            operation: IdentityOperation::Logout,
            session_id: SSH_SESSION_ID.to_string(),
            pid: 100,
            uid: 0,
            auid: Some(1000),
            username: Some("alice".to_string()),
            terminal: Some("/dev/pts/0".to_string()),
            remote_addr: Some(SSH_REMOTE_ADDR.to_string()),
            auth_method: Some("sshd".to_string()),
            success: true,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: base_ts_ns + 8_000_000,
            audit_serial: Some(560),
            source: RawEventSource::Synthetic,
        }),
    ]
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p osiris-generator`
Expected: PASS.

- [ ] **Step 5: Re-export from `generator/src/lib.rs`**

Extend its `pub use scenarios::{...}` list with `persistence_via_systemd_service_scenario, BACKDOOR_UNIT_NAME, BACKDOOR_UNIT_PATH` (needed by `osiris-agent`, same as every earlier scenario's constants).

- [ ] **Step 6: Add the two `AgentConfig` fields**

In `crates/osiris-agent/Cargo.toml`, add under `[dependencies]`:

```toml
osiris-sensors-systemd = { path = "../osiris-sensors/systemd" }
osiris-sensors-persistence = { path = "../osiris-sensors/persistence" }
```

In `crates/osiris-agent/src/config.rs`, add after `identity_audit_log_path`:

```rust
    /// Path to a Linux auditd-style log file for the Systemd sensor's audit
    /// backend, carrying `SERVICE_START`/`SERVICE_STOP` records (plan
    /// Global Constraint #1). Skipped, never silently, if absent or
    /// non-existent.
    #[serde(default)]
    pub systemd_audit_log_path: Option<String>,
    /// Persistence Monitor's config-declared watch targets (plan Global
    /// Constraint #4). Empty by default, in which case the sensor is
    /// skipped (capabilities()-driven, never silently) — same pattern
    /// every other optional sensor config uses, adapted to a list rather
    /// than a single path since this sensor watches several locations at
    /// once.
    #[serde(default)]
    pub persistence_watch_paths: Vec<osiris_sensors_persistence::PersistenceWatchTarget>,
```

Extend `synthetic_scenario`'s doc comment to mention `"persistence_via_systemd_service"`.

- [ ] **Step 7: Write the failing config tests**

Append to `crates/osiris-agent/src/config.rs`'s `#[cfg(test)] mod tests` (read the existing `loads_an_identity_audit_log_path_when_one_is_configured` test first and follow its exact structure):

```rust
    #[test]
    fn defaults_systemd_and_persistence_config_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "enable_synthetic: false\nspool_path: /tmp/spool.ndjson\n\
             status_addr: 127.0.0.1:9200\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(config.systemd_audit_log_path.is_none());
        assert!(config.persistence_watch_paths.is_empty());
    }

    #[test]
    fn loads_persistence_watch_paths_when_configured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "enable_synthetic: false\nspool_path: /tmp/spool.ndjson\n\
             status_addr: 127.0.0.1:9200\n\
             systemd_audit_log_path: /var/log/audit/audit.log\n\
             persistence_watch_paths:\n  \
               - path: /etc/systemd/system\n    kind: systemd_unit_dir\n  \
               - path: /etc/cron.d\n    kind: cron\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert_eq!(
            config.systemd_audit_log_path.as_deref(),
            Some("/var/log/audit/audit.log")
        );
        assert_eq!(config.persistence_watch_paths.len(), 2);
        assert_eq!(config.persistence_watch_paths[0].path, "/etc/systemd/system");
    }
```

Run: `cargo test -p osiris-agent` (expect compile failure first, matching this task's TDD flow, then implement Step 6 if not already done, then PASS).

- [ ] **Step 8: Wire both sensors and the scenario into `agent.rs`**

In `crates/osiris-agent/src/agent.rs`, add to the `use` block:

```rust
use osiris_generator::persistence_via_systemd_service_scenario;
use osiris_sensors_persistence::PersistenceSensor;
use osiris_sensors_systemd::SystemdSensor;
```

In `Agent::start`'s `candidate_sensors` construction, after the `identity_audit_log_path` block:

```rust
        if let Some(path) = &config.systemd_audit_log_path {
            candidate_sensors.push(Box::new(SystemdSensor::new(path.clone())));
        }
        if !config.persistence_watch_paths.is_empty() {
            candidate_sensors.push(Box::new(PersistenceSensor::new(
                config.persistence_watch_paths.clone(),
            )));
        }
```

In the `match config.synthetic_scenario.as_deref()` block, add:

```rust
                Some("persistence_via_systemd_service") => {
                    persistence_via_systemd_service_scenario(base_ts)
                }
```

(insert this arm alongside the existing `Some("ssh_sudo_escalation") => ...` one, before the `Some("exec_chain") | None => ...` fallback).

- [ ] **Step 9: Add the agent-level wiring tests**

Append to `crates/osiris-agent/src/agent.rs`'s `#[cfg(test)] mod tests` (read the existing identity-sensor-selection tests first — likely named something like `the_ssh_sudo_escalation_scenario_is_selectable` — and follow their exact structure, using whichever config-building/host-building helpers that test uses; if the brief's guessed helper names don't match what's actually in this module, use whatever the existing tests use, per the same fallback discipline Phase 4a's Task 5 already established for this exact situation):

```rust
    #[tokio::test]
    async fn the_persistence_via_systemd_service_scenario_is_selectable() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("persistence_via_systemd_service".to_string());
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let snapshot = agent.status_snapshot();
        assert!(snapshot.sensors.iter().any(|s| s.name == "synthetic"));
    }

    #[tokio::test]
    async fn a_configured_but_missing_systemd_audit_log_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.systemd_audit_log_path = Some(
            dir.path()
                .join("missing-audit.log")
                .to_string_lossy()
                .to_string(),
        );
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let snapshot = agent.status_snapshot();
        assert!(snapshot.skipped_sensors.iter().any(|s| s.name == "systemd"));
    }
```

- [ ] **Step 10: Run the full test suites**

Run: `cargo test -p osiris-generator`, `cargo test -p osiris-agent`
Expected: PASS.

Run: `cargo build --workspace --all-targets`
Expected: PASS. If any pre-existing `AgentConfig { ... }` struct literal elsewhere in the workspace (e.g. `crates/osiris-e2e-tests/tests/end_to_end.rs`, which has no `#[derive(Default)]` to fall back on) fails to compile because it doesn't list the two new fields, add `systemd_audit_log_path: None, persistence_watch_paths: vec![],` to each — a minimal, mechanical, non-behavioral fix required purely to keep the workspace compiling, matching the exact situation and exact resolution Phase 4a's own Task 5 already hit and fixed.

- [ ] **Step 11: Commit**

```bash
git add generator/src/scenarios.rs generator/src/lib.rs crates/osiris-agent/src/config.rs crates/osiris-agent/src/agent.rs crates/osiris-agent/Cargo.toml crates/osiris-e2e-tests/tests/end_to_end.rs Cargo.lock
git commit -m "feat(generator,agent): the persistence_via_systemd_service scenario and sensor wiring"
```

## Task 9: `config/rules` — the fourth shipped detection rule (systemd service started via a remote session)

**Files:**
- Create: `config/rules/systemd_service_started_in_remote_session.yaml`
- Modify: `crates/osiris-detect/src/engine.rs` (tests only)

**Interfaces:**
- Consumes: the `CanonicalEvent` JSON projection Task 4 produces — specifically `event_type` and `session.remote_addr`.
- Produces: a fourth rule loaded by the existing `DetectionEngine::load_from_dir(config/rules)` scan, firing as `rule_id: systemd_service_started_in_remote_session`.
- Task 11's e2e asserts this rule fires on the `persistence_via_systemd_service` scenario — **alongside**, not instead of, Phase 4a's `privilege_escalation_to_root_in_remote_session`. Task 8's scenario deliberately reuses that same `PRIVILEGE_UID_CHANGE`-to-root-in-a-remote-session shape as its escalation step (it is the same attacker continuing the same session, not a fresh actor), so both rules' conditions are genuinely satisfied by the one scenario. This is correct, not cross-firing to guard against: Task 11 asserts exactly these two alerts, and that the Phase 2/3 rules (web-root write, suspicious-TLD DNS) — which this scenario triggers no file-write or DNS event for — stay silent.

**No `osiris-detect` source changes (Global Constraint #9)** — and this task must verify that claim against the real code before writing the rule, not assume it from the constraint's prose. Open `crates/osiris-detect/src/eval.rs` and `crates/osiris-detect/src/engine.rs` and confirm all four of the following. If any is false, **stop and report it**, because the rule below silently depends on every one of them:

1. `eval::field_value` splits the rule's `field` on `.` and walks the serialized event with `current.get(segment)?` — so `session.remote_addr` resolves with no new code, because `CanonicalEvent` serializes `session` under exactly that JSON name.
2. `eval::field_value` returns `None` for an explicit JSON `null`, not `Some(Value::Null)`. That is what makes a condition on `session.remote_addr` double as an existence check: an event with no session, or a session whose `remote_addr` is `null`, resolves to `None`.
3. `engine::evaluate_rule` short-circuits the whole rule on such a field via `?`, so a missing field is a non-match rather than a `null == expected` comparison. A `SERVICE_START` event with no observed session (plan Global Constraint #3's honest disclosure — e.g. a unit started at boot with no D-Bus caller) therefore cannot fire this rule, which is correct: there is no "remote session" to report.
4. `DetectionEngine::load_from_dir` globs `*.yaml`/`*.yml`, sorts by file name, and constructs a `Rule` per file — so a fourth file is picked up with no registration step anywhere.

Also confirm the rule *schema* from `crates/osiris-detect/src/rule.rs`: `RuleFile` is `#[serde(deny_unknown_fields)]` with exactly `id`, `version`, `severity`, `match`; every `Condition` requires `field`, `op`, `value` **and a non-blank `reason`**; `Operator` is exactly `{eq, ne, contains, starts_with, ends_with, in}`.

- [ ] **Step 1: Write the failing rule tests**

Append to `crates/osiris-detect/src/engine.rs`'s `#[cfg(test)] mod tests`. Read the module's existing `escalation_event`-style fixture helper first (from Phase 4a's shipped rule test) and follow its exact structure/conventions.

```rust
    fn systemd_start_event(unit_name: &str, remote_addr: Option<&str>, timestamp: u64) -> CanonicalEvent {
        let mut event = sample_event(600, timestamp);
        event.event_type = osiris_schema::EventType::ServiceStart;
        event.category = osiris_schema::Category::Systemd;
        event.service = Some(osiris_schema::ServiceRef {
            unit_name: unit_name.to_string(),
            unit_type: "service".to_string(),
            action: "start".to_string(),
        });
        event.session = remote_addr.map(|addr| osiris_schema::SessionRef {
            session_id: "3".to_string(),
            tty: None,
            remote_addr: Some(addr.to_string()),
            auth_method: Some("sshd".to_string()),
        });
        event
    }

    #[test]
    fn the_shipped_systemd_remote_start_rule_loads_and_fires_on_its_positive_fixture_only() {
        let engine = DetectionEngine::load_from_dir("../../config/rules").unwrap();
        let event = systemd_start_event("backdoor.service", Some("198.51.100.10"), 1000);
        let alerts = engine.evaluate(&event);
        let matched: Vec<_> = alerts
            .iter()
            .filter(|a| a.rule_id() == "systemd_service_started_in_remote_session")
            .collect();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].severity(), osiris_schema::Severity::High);
        assert_eq!(matched[0].reasons().len(), 2);
    }

    #[test]
    fn the_shipped_systemd_remote_start_rule_does_not_fire_on_a_local_or_sessionless_start() {
        let engine = DetectionEngine::load_from_dir("../../config/rules").unwrap();
        let local = systemd_start_event("cron.service", None, 1000);
        assert!(engine
            .evaluate(&local)
            .iter()
            .all(|a| a.rule_id() != "systemd_service_started_in_remote_session"));
    }

    #[test]
    fn the_shipped_systemd_remote_start_rule_does_not_fire_on_a_service_stop() {
        let engine = DetectionEngine::load_from_dir("../../config/rules").unwrap();
        let mut event = systemd_start_event("backdoor.service", Some("198.51.100.10"), 1000);
        event.event_type = osiris_schema::EventType::ServiceStop;
        assert!(engine
            .evaluate(&event)
            .iter()
            .all(|a| a.rule_id() != "systemd_service_started_in_remote_session"));
    }

    #[test]
    fn all_four_shipped_rules_load_together_without_cross_firing() {
        let engine = DetectionEngine::load_from_dir("../../config/rules").unwrap();
        let event = systemd_start_event("backdoor.service", Some("198.51.100.10"), 1000);
        let alerts = engine.evaluate(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id(), "systemd_service_started_in_remote_session");
    }
```

(Adapt the exact helper names — `DetectionEngine::load_from_dir`'s relative path, `Alert`'s accessor names — to whatever Phase 4a's own shipped-rule tests in this same file actually use; read them first, this task's tests must match that established convention exactly, not invent a parallel one.)

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p osiris-detect`
Expected: FAIL — `could not read .../systemd_service_started_in_remote_session.yaml` (file not found) on the tests that need it to fire, and the four-rules-count assertion fails.

- [ ] **Step 3: Write the rule YAML exactly as specified**

Create `config/rules/systemd_service_started_in_remote_session.yaml`:

```yaml
# Detects a systemd service starting inside a session that was opened from
# a remote address — the same "actor plus artifact, not artifact alone"
# shape as Phase 4a's privilege_escalation_to_root_in_remote_session, now
# applied to Phase 4b's persistence mechanism: installing and starting a
# backdoor service is the natural continuation of a remote escalation, and
# neither half is suspicious alone (services start constantly at boot and
# via local admin action; remote sessions are ordinary).
#
# `session.remote_addr ne ""` relies on the same null-handling `eval::
# field_value`/`engine::evaluate_rule` already provide (Phase 4a plan
# Global Constraint #9's precedent, reaffirmed by this phase's Global
# Constraint #9): a SERVICE_START with no observed session (e.g. one
# started at boot, with no D-Bus caller to attribute) resolves to a
# non-match, not a fabricated "local" classification.
#
# MITRE ATT&CK: T1543.002 (Create or Modify System Process: Systemd
# Service), reached over T1021.004 (Remote Services: SSH).
id: systemd_service_started_in_remote_session
version: 1
severity: HIGH
match:
  - field: event_type
    op: eq
    value: "SERVICE_START"
    reason: "A systemd service transitioned to the running state"
  - field: session.remote_addr
    op: ne
    value: ""
    reason: "The service was started inside a session opened from a remote network address (an SSH login), not a local console or an unattributed system service"
```

Run: `cargo test -p osiris-detect`
Expected: PASS.

- [ ] **Step 4: Run the full workspace build**

Run: `cargo build --workspace --all-targets`
Expected: PASS.

- [ ] **Step 5: Confirm the diff shape**

Run: `git status --short config/rules crates/osiris-detect` and `git diff crates/osiris-detect`
Expected: exactly one new YAML file, and every changed line in `crates/osiris-detect/src/engine.rs` is inside its `#[cfg(test)] mod tests` block — Global Constraint #9 requires this, verify it directly rather than assuming it.

- [ ] **Step 6: Commit**

```bash
git add config/rules/systemd_service_started_in_remote_session.yaml crates/osiris-detect/src/engine.rs
git commit -m "feat(rules): ship the systemd-service-started-in-a-remote-session rule"
```

## Task 10: `osiris-api` — `GET /api/v1/systemd/story?unit_name=…`

**Files:**
- Modify: `crates/osiris-api/src/lib.rs`

**Interfaces:**
- Consumes: Task 7's `QueryPlan.unit_name`, plus the existing `Storage::query`/`Storage::query_alerts` surface. No new `Storage` method.
- Produces:
  - Route `GET /api/v1/systemd/story?unit_name=…`.
  - `SystemdStoryQuery { unit_name: Option<String> }` and `SystemdStory { events: Vec<CanonicalEvent>, alerts: Vec<Alert> }` — the same `{ events, alerts }` shape as `FileStory`/`NetworkStory`/`IdentityStory` (plan Global Constraint #10 carries the precedent forward).
- No `osiris-server` change and no `osiris-cli` verb (Global Constraint #10).

**Before writing any code**, read `crates/osiris-api/src/lib.rs`'s `identity_story_handler` end to end (already read in full while planning this task) — this task mirrors its single-filter, no-dedup shape exactly (unlike `network_story_handler`/`file_story_handler`, which union across multiple queries and therefore do need a `HashMap`-based dedup pass; a single `unit_name` filter needs none of that, same as `identity_story_handler`'s own `session_id`/`uid` filters).

- [ ] **Step 1: Write the failing handler tests**

Append to `crates/osiris-api/src/lib.rs`'s `#[cfg(test)] mod tests`. Read the existing `session_event` test helper first and follow its structure for a new `systemd_event` helper:

```rust
    fn systemd_event(unit_name: &str, event_type: EventType, timestamp: u64) -> CanonicalEvent {
        let mut event = sample_event(700, None, timestamp);
        event.category = Category::Systemd;
        event.event_type = event_type;
        event.service = Some(osiris_schema::ServiceRef {
            unit_name: unit_name.to_string(),
            unit_type: "service".to_string(),
            action: "start".to_string(),
        });
        event
    }

    #[tokio::test]
    async fn systemd_story_returns_400_when_unit_name_is_missing() {
        let (_dir, storage) = test_storage();
        let result = systemd_story_handler(State(storage), Query(SystemdStoryQuery { unit_name: None }))
            .await;
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn systemd_story_returns_every_event_for_the_named_unit() {
        let (_dir, storage) = test_storage();
        let start = systemd_event("backdoor.service", EventType::ServiceStart, 1000);
        let stop = systemd_event("backdoor.service", EventType::ServiceStop, 2000);
        let other_unit = systemd_event("sshd.service", EventType::ServiceStart, 3000);
        storage
            .batch_write(&[start.clone(), stop.clone(), other_unit])
            .unwrap();

        let Json(story) = systemd_story_handler(
            State(storage),
            Query(SystemdStoryQuery {
                unit_name: Some("backdoor.service".to_string()),
            }),
        )
        .await
        .unwrap();
        assert_eq!(story.events.len(), 2);
        let ids: Vec<_> = story.events.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&start.event_id));
        assert!(ids.contains(&stop.event_id));
    }

    #[tokio::test]
    async fn systemd_story_returns_an_empty_story_rather_than_404_for_an_unknown_unit() {
        let (_dir, storage) = test_storage();
        let Json(story) = systemd_story_handler(
            State(storage),
            Query(SystemdStoryQuery {
                unit_name: Some("does-not-exist.service".to_string()),
            }),
        )
        .await
        .unwrap();
        assert!(story.events.is_empty());
        assert!(story.alerts.is_empty());
    }
```

(If `sample_event`'s actual signature in this file differs from the guessed `sample_event(700, None, timestamp)` shown above — e.g. a different parameter order or count — read the file's real helper signature first and adapt the calls to match it exactly; the fixture shape, not the exact call syntax, is what this test depends on.)

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p osiris-api`
Expected: FAIL to compile — `cannot find function systemd_story_handler`, `cannot find type SystemdStoryQuery`.

- [ ] **Step 3: Implement the handler**

In `crates/osiris-api/src/lib.rs`, after `identity_story_handler` and before its `#[cfg(test)]` module:

```rust
#[derive(Debug, Deserialize)]
struct SystemdStoryQuery {
    unit_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct SystemdStory {
    events: Vec<CanonicalEvent>,
    alerts: Vec<Alert>,
}

/// Composed query implementing this phase's Global Constraint #12 and
/// ARCHITECTURE.md §12.1's `*_story` shape. One `unit_name` filter returns
/// a unit's whole observed history regardless of which sensor produced
/// which part of it — Task 4's Normalize populates `service.unit_name`
/// identically for the audit-backed Systemd sensor's `SERVICE_START`/`STOP`
/// events and for Persistence Monitor's unit-*file*-lifecycle events
/// (`SERVICE_CREATE`/`MODIFY`/`DELETE`, `TIMER_CREATE`/`MODIFY`), so this
/// one indexed column already spans both without a union query.
async fn systemd_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<SystemdStoryQuery>,
) -> Result<Json<SystemdStory>, (StatusCode, String)> {
    if q.unit_name.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "must provide unit_name".to_string(),
        ));
    }

    let (events, alerts) = tokio::task::spawn_blocking(move || {
        let mut plan = QueryPlan::new();
        plan.unit_name = q.unit_name.clone();
        plan.limit = 10_000;
        let mut events = storage.query(&plan)?;
        events.sort_by_key(|e| (e.timestamp, e.event_id));

        let evidence_ids: Vec<uuid::Uuid> = events.iter().map(|e| e.event_id).collect();
        let alerts = if evidence_ids.is_empty() {
            vec![]
        } else {
            let mut alert_plan = AlertQueryPlan::new();
            alert_plan.evidence_event_ids = evidence_ids;
            alert_plan.limit = 10_000;
            storage.query_alerts(&alert_plan)?
        };

        Ok::<_, osiris_storage::StorageError>((events, alerts))
    })
    .await
    .unwrap()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(SystemdStory { events, alerts }))
}
```

- [ ] **Step 4: Register the route**

In `build_router`, add:

```rust
        .route("/api/v1/systemd/story", get(systemd_story_handler))
```

(placed after the existing `.route("/api/v1/identity/story", get(identity_story_handler))` line).

- [ ] **Step 5: Run the tests**

Run: `cargo test -p osiris-api`
Expected: PASS.

- [ ] **Step 6: Run the full workspace build**

Run: `cargo build --workspace --all-targets`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/osiris-api/src/lib.rs
git commit -m "feat(api): GET /api/v1/systemd/story"
```

## Task 11: `osiris-e2e-tests` — prove the flagship scenario end-to-end

**Files:**
- Modify: `crates/osiris-e2e-tests/tests/end_to_end.rs`

**Interfaces:**
- Consumes: every prior task's public surface, exercised through the real Agent/Server/API — no new production code.
- Produces: `persistence_via_systemd_service_scenario_flows_end_to_end_and_triggers_detection`, following `ssh_sudo_escalation_flows_end_to_end_and_triggers_detection`'s (line ~676) structure exactly.

**Before writing any code**, re-confirm three facts already established while writing this plan, so the test's own assertions are not guesses:
1. The scenario (Task 8) has 9 events across exactly four categories present in this trace — `PROCESS` (3: sshd/bash/sudo execs), `IDENTITY` (2: login/logout), `PRIVILEGE` (2: sudo, uid-change-to-root), `SYSTEMD` (2: the persistence-monitor-observed `SERVICE_CREATE` for the new unit file, and the audit-observed `SERVICE_START`). No `PERSISTENCE`-category event and no `FILE`/`NETWORK` event occur in this scenario — Global Constraint #1 routes a `SystemdUnit` checkpoint entirely into `SYSTEMD`, never `PERSISTENCE`.
2. Every event carries the session `SSH_SESSION_ID` ("3") **except** the pre-login sshd exec (as in every prior identity-chain scenario) **and** the `SERVICE_CREATE` event — Persistence Monitor's scan is never triggered by a process, so `normalize_persistence_event` sets `session: None` unconditionally (Global Constraint #3), and `attach_session`'s very first check (`event.process.as_ref()` — `None` for this event) returns immediately without inferring one. The `SERVICE_START` event, by contrast, carries the session directly observed from its own `ses=`, which Task 1's fix preserves and Enrich then fills out to the full record (remote_addr/auth_method) via `record_for`.
3. Two alerts fire, not one: `systemd_service_started_in_remote_session` (this phase) and `privilege_escalation_to_root_in_remote_session` (Phase 4a) — Task 9's own note above explains why both are genuinely satisfied by this one scenario. The Phase 2/3 rules (`shell_wrote_file_to_web_root`, `dns_query_to_suspicious_tld`) must stay silent — this scenario has no `FILE_WRITE`/`DNS_QUERY` event for them to match at all.

- [ ] **Step 1: Write the test**

Append to `crates/osiris-e2e-tests/tests/end_to_end.rs`, after `ssh_sudo_escalation_flows_end_to_end_and_triggers_detection` and before `urlencoding_lite`:

```rust
/// Phase 4b's flagship trace: continuing the same SSH-login-then-sudo-to-
/// root escalation `ssh_sudo_escalation_flows_end_to_end_and_triggers_detection`
/// proves, the same attacker now installs a backdoor systemd unit file
/// (observed by Persistence Monitor's periodic scan-and-diff — unattributed,
/// no pid triggered it) and starts it (observed by the audit-backed Systemd
/// sensor, whose record's own `ses=` carries the SSH session directly) — all
/// through the real Agent, Server, and HTTP API.
///
/// Verifies, in order: all 9 events landed across the four categories this
/// trace touches; the `SERVICE_CREATE` event carries no session (Global
/// Constraint #3 — the scanner is not triggered by a process) while the
/// `SERVICE_START` event's directly-observed session is enriched to the full
/// record (proof that Task 1's fix and this phase's direct-observation
/// normalize combine correctly); `SERVICE_START` carries zero relationship
/// edges (Global Constraint #3's "no fabricated actor" ruling, asserted as
/// an absence check the way Phase 4a's own final review required); both the
/// new systemd rule and Phase 4a's escalation rule fired — and only those
/// two; and the new Systemd Story endpoint returns exactly the two
/// `backdoor.service`-named events plus the one alert that cites either of
/// them as evidence.
#[tokio::test(flavor = "multi_thread")]
async fn persistence_via_systemd_service_scenario_flows_end_to_end_and_triggers_detection() {
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("spool.ndjson");
    let db_path = dir.path().join("events.db");

    let host = HostRef {
        host_id: Uuid::new_v4(),
        hostname: "e2e-test-host".to_string(),
        distro: "test".to_string(),
        kernel_version: "test".to_string(),
        cloud: None,
    };

    let agent_config = AgentConfig {
        audit_log_path: None,
        fs_audit_log_path: None,
        network_proc_root: None,
        identity_audit_log_path: None,
        systemd_audit_log_path: None,
        persistence_watch_paths: vec![],
        enable_synthetic: true,
        synthetic_scenario: Some("persistence_via_systemd_service".to_string()),
        spool_path: spool_path.to_string_lossy().to_string(),
        status_addr: "127.0.0.1:0".to_string(),
    };
    let agent = Agent::start(agent_config, host, "e2e-boot".to_string())
        .await
        .unwrap();

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(&db_path).unwrap());

    // The real shipped rules directory — now four rules.
    let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
    let detection_engine = Arc::new(DetectionEngine::load_from_dir(&rules_dir).unwrap());
    assert!(detection_engine.rule_count() >= 4);

    let ingestion_cancellation = CancellationToken::new();
    tokio::spawn(run_ingestion_loop(
        spool_path.clone(),
        storage.clone(),
        detection_engine,
        Duration::from_millis(50),
        ingestion_cancellation.clone(),
    ));

    // 9-event scenario, same generous budget as the ssh_sudo_escalation e2e.
    tokio::time::sleep(Duration::from_millis(1400)).await;
    agent.shutdown().await;
    ingestion_cancellation.cancel();

    // 1. Storage directly: all 9 events landed, across exactly four
    //    categories (no FILE, no NETWORK, no generic PERSISTENCE — this
    //    scenario's one checkpoint is a SystemdUnit, which Global Constraint
    //    #1 routes entirely into SYSTEMD).
    let events = storage.query(&QueryPlan::new()).unwrap();
    assert_eq!(
        events.len(),
        9,
        "expected sshd/bash/sudo execs, login, sudo, uid change, unit-file create, service start, logout"
    );
    // `Category` derives neither `Hash` nor `Ord` (schema-frozen, Global
    // Constraint #6 — not something this phase may add just for a test), so
    // this checks membership directly rather than building a `HashSet`.
    assert!(
        events
            .iter()
            .all(|e| matches!(
                e.category,
                Category::Process | Category::Identity | Category::Privilege | Category::Systemd
            )),
        "no FILE/NETWORK/PERSISTENCE event exists in this scenario"
    );
    for expected in [
        Category::Process,
        Category::Identity,
        Category::Privilege,
        Category::Systemd,
    ] {
        assert!(
            events.iter().any(|e| e.category == expected),
            "expected at least one {expected:?} event"
        );
    }

    // 2. The two SYSTEMD-category events, told apart by event_type: the
    //    Persistence-Monitor-observed unit-file creation, and the
    //    audit-observed service start.
    let unit_create = events
        .iter()
        .find(|e| e.event_type == EventType::ServiceCreate)
        .expect("the SERVICE_CREATE event must be present");
    let service_start = events
        .iter()
        .find(|e| e.event_type == EventType::ServiceStart)
        .expect("the SERVICE_START event must be present");
    assert_eq!(unit_create.service.as_ref().unwrap().unit_name, "backdoor.service");
    assert_eq!(service_start.service.as_ref().unwrap().unit_name, "backdoor.service");

    // 3. Session propagation (Global Constraint #3's disclosed asymmetry):
    //    SERVICE_CREATE carries none at all (the scanner has no process to
    //    attribute it to); SERVICE_START carries the SSH session, enriched
    //    to the full record — proof Task 1's fix and this phase's direct
    //    observation combine correctly, not just in the pipeline unit test.
    assert!(
        unit_create.session.is_none(),
        "a Persistence-Monitor-observed event must carry no session — it was never triggered by a process"
    );
    let start_session = service_start
        .session
        .as_ref()
        .expect("SERVICE_START's own ses= must be observed and preserved");
    assert_eq!(start_session.session_id, "3");
    assert_eq!(
        start_session.remote_addr.as_deref(),
        Some("198.51.100.10"),
        "the observed session id must be enriched to the full record, not left minimal"
    );
    assert_eq!(start_session.auth_method.as_deref(), Some("sshd"));

    let sshd_exec = events
        .iter()
        .find(|e| {
            e.event_type == EventType::ProcessExec
                && e.process.as_ref().map(|p| p.pid) == Some(100)
        })
        .expect("the sshd exec must be present");
    assert!(
        sshd_exec.session.is_none(),
        "the exec that preceded the login must not be retro-attributed to it"
    );

    for event in &events {
        if event.event_id == sshd_exec.event_id || event.event_id == unit_create.event_id {
            continue;
        }
        let session = event
            .session
            .as_ref()
            .unwrap_or_else(|| panic!("{:?} must carry the session", event.event_type));
        assert_eq!(session.session_id, "3");
    }

    // 4. Global Constraint #3: no entity-graph edges for either SYSTEMD
    //    event this phase adds — asserted as an absence, on
    //    event.relationships directly, not inferred from a Story join.
    assert!(
        service_start.relationships.is_empty(),
        "a SERVICE_START event must carry zero relationship edges — systemd's own \
         pid=1 is not an attacker-controlled process to graph an edge from"
    );
    assert!(
        unit_create.relationships.is_empty(),
        "a SERVICE_CREATE event must carry zero relationship edges — the scanner \
         observed a path on disk, not a process's action"
    );

    // ...while the pre-existing edges from Phase 4a's own escalation step
    // are still present, exactly as ssh_sudo_escalation's own e2e proved —
    // this phase changes nothing about them.
    let escalation = events
        .iter()
        .find(|e| e.event_type == EventType::PrivilegeUidChange)
        .expect("the PRIVILEGE_UID_CHANGE event must be present");
    assert_eq!(
        escalation
            .relationships
            .iter()
            .filter(|r| r.relation == Relation::ExecutedAs)
            .count(),
        1
    );

    // 5. Storage's new unit_name filter works on real ingested rows (Task 7).
    let mut plan = QueryPlan::new();
    plan.unit_name = Some("backdoor.service".to_string());
    assert_eq!(
        storage.query(&plan).unwrap().len(),
        2,
        "both the create and the start belong to backdoor.service"
    );

    // 6. Over real HTTP: both alerts fired, and only those two.
    let app = build_router(storage.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let alerts: serde_json::Value = client
        .get(format!("http://{}/api/v1/alerts", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let alerts_array = alerts.as_array().unwrap();
    assert_eq!(
        alerts_array.len(),
        2,
        "exactly two alerts: the new systemd rule and Phase 4a's escalation rule \
         — the same attacker continuing the same session, not cross-firing"
    );
    let rule_ids: std::collections::HashSet<_> = alerts_array
        .iter()
        .map(|a| a["rule_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        rule_ids,
        std::collections::HashSet::from([
            "systemd_service_started_in_remote_session".to_string(),
            "privilege_escalation_to_root_in_remote_session".to_string(),
        ]),
        "the Phase 2/3 rules must stay silent — this scenario has no FILE_WRITE/DNS_QUERY event"
    );
    for alert in alerts_array {
        let reasons = alert["reasons"].as_array().unwrap();
        assert!(!reasons.is_empty());
        assert!(reasons.iter().all(|r| !r.as_str().unwrap().trim().is_empty()));
        assert_eq!(alert["rule_content_hash"].as_str().unwrap().len(), 64);
    }

    // 7. The new Systemd Story endpoint (Task 10) over real HTTP: exactly
    //    the two backdoor.service events, plus the one alert that cites
    //    either of them as evidence (the escalation alert's evidence is the
    //    PRIVILEGE_UID_CHANGE event, which this unit-scoped story does not
    //    include).
    let story: serde_json::Value = client
        .get(format!("http://{}/api/v1/systemd/story?unit_name=backdoor.service", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let story_events = story["events"].as_array().unwrap();
    assert_eq!(story_events.len(), 2);
    let story_event_types: std::collections::HashSet<_> = story_events
        .iter()
        .map(|e| e["event_type"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        story_event_types,
        std::collections::HashSet::from([
            "SERVICE_CREATE".to_string(),
            "SERVICE_START".to_string(),
        ])
    );
    let story_alerts = story["alerts"].as_array().unwrap();
    assert_eq!(
        story_alerts.len(),
        1,
        "only the systemd rule's alert cites a backdoor.service event as evidence"
    );
    assert_eq!(
        story_alerts[0]["rule_id"].as_str().unwrap(),
        "systemd_service_started_in_remote_session"
    );

    // 8. The real CLI binary still works against this richer dataset
    //    (regression check, unchanged from Phase 2/3/4a).
    let cli_binary = cli_binary_path();
    let output = std::process::Command::new(&cli_binary)
        .args(["--server", &format!("http://{}", addr), "--format", "json", "events"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 9);
}
```

Add `Category` to the existing `use osiris_schema::{...}` import line at the top of the file (it currently imports `EntityRef, EventType, HostRef, Relation` but not `Category`).

- [ ] **Step 2: Run the test to verify it currently fails to compile**

Run: `cargo test -p osiris-e2e-tests persistence_via_systemd_service`
Expected: FAIL to compile — `AgentConfig` has no field `systemd_audit_log_path`/`persistence_watch_paths` yet if Task 8 has not landed; `osiris_generator`/sensors not wired yet. Since this task runs after Tasks 1-10 in the dispatch order, by the time this task executes the workspace should already build; this step's real purpose is to confirm the *new test itself* fails before this task existed (i.e., re-run on a checkout before this task's own diff) — if Tasks 1-10 are already committed, skip straight to Step 3 and treat a clean compile-and-run as this task's own red/green pair (compile succeeds because the prior tasks' surface already exists; the test's assertions are what were unverified until now).

- [ ] **Step 3: Run it**

Run: `cargo test -p osiris-e2e-tests persistence_via_systemd_service -- --nocapture`
Expected: PASS. If any assertion fails, do not weaken the assertion to match — re-derive the expected value from the real, current behavior of Tasks 1-10's code (re-read the specific normalize/enrich/rule function in question) and fix either the test's expectation or, if the mismatch reveals a genuine bug in an earlier task, that task's code, per this plan's Global Constraints.

- [ ] **Step 4: Run the full end-to-end suite and the full workspace test suite**

Run: `cargo test -p osiris-e2e-tests`
Expected: PASS — this new test plus all four pre-existing e2e tests (`synthetic_exec_chain_...`, `web_shell_drop_...`, `network_beacon_...`, `ssh_sudo_escalation_...`).

Run: `cargo test --workspace`
Expected: PASS — every test in the workspace, confirming this phase's whole vertical slice.

Run: `cargo build --workspace --all-targets`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-e2e-tests/tests/end_to_end.rs
git commit -m "test(e2e): prove the Phase 4b systemd/persistence vertical slice end-to-end"
```

## Self-Review

**Spec coverage against ARCHITECTURE.md:**
- §4.3 (sensor catalog): both new sensor rows shipped — Systemd (audit-backed, Task 5) and Persistence Monitor (scan-and-diff, Task 6). ✓
- §9.2-9.4 (envelope/taxonomy/relationships): all seven `EventType` variants this phase needs already existed from Phase 0 and are now reachable (Task 4); no new `Relation`/`EntityRef` variant was needed or added, matching Global Constraint #3's ruling that no honest edge exists to mint this phase. ✓
- §89/Phase 4 roadmap line: both halves ("Systemd Sensor" and "Persistence Monitor") shipped in one phase, completing the roadmap line Phase 4a began. ✓
- §26's worked trace pattern (identity → process → privilege → \[new category\]) extended one category further, exactly as Phase 4a extended it from Phase 3's file/network trace. ✓

**Placeholder scan:** re-read Tasks 1-11 above in full; no `TODO`, `unimplemented!()`, `todo!()`, or "left as an exercise" language anywhere in the code blocks. Every task's Step 1 test is a complete, runnable test with concrete fixture values, not a stub.

**Type-consistency check across all 11 tasks:**
- `SystemdEventRaw`/`PersistenceEventRaw` (Task 3) field lists match exactly what Task 4's `normalize_systemd_event`/`normalize_persistence_event` consume, what Task 5/6's sensors construct, and what Task 8's scenario builds — verified by re-reading all four tasks' code blocks side by side while writing Task 11 (which exercises every one of these fields transitively through the real Agent).
- `PersistenceWatchTarget`/`PersistenceWatchKind` (Task 6) match the field names Task 8's `AgentConfig.persistence_watch_paths` and its config-loading test use (`path`, `kind`).
- `QueryPlan.unit_name` (Task 7) matches the field name Task 10's `systemd_story_handler` and Task 11's e2e test both use.
- `EventType::ServiceCreate`/`ServiceStart`/`TimerModify`/`PersistenceCreated` etc. (already frozen in `osiris-schema` per Global Constraint #6) are used identically across Tasks 4, 9, 10, and 11 — no task invents a variant name that doesn't exist in `event_type.rs`.
- `Category` derives `Copy, PartialEq, Eq` but not `Hash`/`Ord` (verified directly against `crates/osiris-schema/src/event_type.rs` while writing Task 11) — Task 11's category-membership assertions are written as direct `matches!`/`.any()` checks, not a `HashSet<Category>`, so this task does not silently depend on a schema trait it doesn't have (and Global Constraint #6 forbids adding one just for a test's convenience).

**Cross-task interface finding caught by this Self-Review pass:** Task 9's original interfaces note claimed the new systemd rule fires "and only this rule" on the Task 8 scenario. Re-deriving the scenario's actual event content against the *already-shipped* (Phase 4a) `privilege_escalation_to_root_in_remote_session` rule's conditions (`PRIVILEGE_UID_CHANGE` + `target_uid: 0` + `session.remote_addr ne ""`) shows the scenario's own uid-change-to-root-in-a-remote-session step genuinely satisfies that rule too — because Task 8 deliberately continues Phase 4a's own escalation shape rather than starting a fresh, unescalated actor. This is correct scenario design (an attacker who is already root is exactly who installs a backdoor service), not a flaw to fix in Task 8 — the flaw was Task 9's overclaiming sentence, corrected above, and Task 11 is written to assert both alerts fire together rather than asserting a false single-alert count that would have failed on first execution.

**Result:** plan is complete and internally consistent. Ready to execute task-by-task.
