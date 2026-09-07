# Phase 4a — Identity + Privilege + SSH/sudo Correlation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the first half of ARCHITECTURE.md §29's Phase 4 line — a real Identity Sensor (Linux Audit `USER_*` record backend), Privilege telemetry emitted by that same sensor's audit parser, and SSH/sudo correlation as Enrichment-stage entity-graph edges (`TRIGGERED_BY_SESSION`, `EXECUTED_AS`) — so that §26's worked trace becomes reproducible end-to-end from its very first step (`sshd accepts a connection → PAM/audit records session start → Identity Sensor (audit backend) emits RawEvent{session_login}`) through process, privilege, file and network events that all carry the same `session_id`. Systemd and Persistence are deferred to an explicit Phase 4b (see "Deferred to Phase 4b" at the end of this document).

**Architecture:** A new `osiris-sensors-identity` crate tails a configurable auditd-format log file with the shared `osiris_fileutil::LineTailer` (the exact mechanism Phase 1's Process/Exec and Phase 2's Filesystem sensors already use) and parses two *disjoint* families of records from it: the `USER_LOGIN`/`USER_LOGOUT`/`USER_START`/`USER_END` session records (→ `RawEvent::Identity`) and the privilege-transition records `SYSCALL syscall=105` (setuid), `SYSCALL syscall=106` (setgid) and `USER_CMD` (sudo) (→ `RawEvent::Privilege`). ARCHITECTURE.md §4.3 has no separate "Privilege" sensor row; §9.3's `PRIVILEGE:` taxonomy row and §26's trace both place privilege telemetry with whichever sensor observes the uid/gid/sudo transition, and the audit backend that already sees `USER_*` records sees these too — so one crate, one tail, two `RawEvent` variants (Global Constraint #4). Correlation is *not* built into the sensor (§4.2 forbids cross-sensor reference): the Pipeline's Enrich stage gains a `SessionResolver` that learns `pid → session_id` from `SESSION_LOGIN`/`SESSION_CREATE` events and propagates it down the process tree by ppid inheritance — exactly §26 step 3's "attach session_id from the Identity Sensor's earlier SESSION_LOGIN (looked up via the Process Resolver's session-to-process linkage, populated at login/exec time)". That resolver populates `CanonicalEvent.session` on every downstream event and writes the two already-frozen-but-until-now-unused edges from §9.4. Storage gains two indexed columns and two `QueryPlan` filters; the API gains `GET /api/v1/identity/story`, mirroring Phase 2's File Story and Phase 3's Network Story exactly. No stateful correlation/graph-walk engine is built — that is explicitly Phase 6 (Global Constraint #12).

**Tech Stack:** Rust (edition 2021), Tokio, `async-trait`, `axum`, `rusqlite` (`bundled`), `serde_yaml` (the new rule file) — all already present in `[workspace.dependencies]`. No new third-party crates are introduced by this phase.

**Spec:** `ARCHITECTURE.md` (project root) — primarily §2.1 (layering rule), §4.1/§4.2/§4.3 (Sensor trait, sensor independence, the Identity/Session row's `Linux Audit (PAM, login)` primary and `utmp/wtmp polling` fallback backends), §6 (telemetry levels — Identity is a MINIMAL-row sensor), §7.1 (Event Pipeline stages), §8 (Event Bus lanes), §9.2/§9.3/§9.4 (Event Schema v1 envelope — `UserRef`/`SessionRef` already exist from Phase 0, the `IDENTITY:`/`PRIVILEGE:` taxonomy rows already exist, `EntityRef::User`/`EntityRef::Session` already exist, `Relation::ExecutedAs`/`Relation::TriggeredBySession` already exist — this phase wires existing schema, it does not extend it; see Global Constraint #7), §10.1 (Storage trait), §11.1/§11.2 (Detection Engine + the structural explanation requirement — no engine changes, only a new rule), §11.3 (Correlation Engine — explicitly *not* built this phase, see Global Constraint #12), §12.1 (Investigation Engine's `*_story` shape), §12.4 (Timeline), §12.5 (Entity Graph), §14.2 (endpoint surface), §18/§27 (privilege boundary + dependency graph), §24 (repo structure), §26 (the worked trace this phase completes the identity half of), §29's Phase 4 line. The immediate prior art is Phase 3's plan (`docs/superpowers/plans/2026-09-06-phase-3-network-dns-vertical-slice.md`) and Phase 2's (`docs/superpowers/plans/2026-09-03-phase-2-filesystem-vertical-slice.md`); several of their Global Constraints are reaffirmed here rather than restated in full (marked "carried from Phase 2/3" below).

## Global Constraints — scope decisions made for this plan (read before dispatching any task)

The development environment is unchanged from Phase 1/2/3: Windows, no Linux kernel, no clang/libbpf toolchain, no root, no real `/proc` filesystem, no auditd. Phase 1/2/3's response was never to fake a sensor but to implement a *documented fallback backend* as portable Rust, tested against fixture files in the real backend's exact text format. This plan applies the same strategy to the Identity Sensor. Every decision below is disclosed and reversible; every task's requirements implicitly include this section.

1. **This plan is Phase 4a, not all of Phase 4.** ARCHITECTURE.md §29's Phase 4 line names five deliverables: Identity Sensor, Privilege telemetry, SSH/sudo correlation, Systemd Sensor, Persistence Monitor. Shipping all five as one plan would produce roughly 13 tasks touching four new crates and two new Story endpoints — nearly double Phase 3's 8-task/one-new-crate density, with a review-loop cost (one fresh implementer plus one independent reviewer per task, plus one whole-branch review) that scales with task count. The split is drawn where the deliverables actually couple: **Identity + Privilege + SSH/sudo correlation are one indivisible unit** (privilege records come out of the *same* audit tail as identity records; the correlation edges are meaningless without both), while **Systemd + Persistence share nothing with them** — different backends (`systemctl list-units` subprocess output; filesystem path scanning), different `EventType` families, different Story shape, and zero dependency on anything this plan builds beyond the pipeline pattern it re-uses. The roadmap's own stated headline for Phase 4 — "the Correlation Engine's `BehavioralChain` first becomes genuinely multi-category (identity→process→file→network, matching §26's worked trace in full)" — is satisfied *entirely* by this plan: §26's trace contains no systemd unit and no persistence path. **This plan is therefore Phase 4a; Phase 4b (Systemd Sensor + Persistence Monitor) is specified in the "Deferred to Phase 4b" section at the end of this document so the next planning session does not have to re-derive this decision.** The plan file, its title, and its Goal line all say "Phase 4a" explicitly so nobody mistakes it for the whole phase.

2. **The Identity Sensor's only backend is the audit log file — no utmp/wtmp, no `/proc/<pid>/loginuid`, no eBPF.** §4.3's Identity/Session row lists `Linux Audit (PAM, login)`, `/var/run/utmp`, `/proc/<pid>/loginuid` as primary and `utmp/wtmp polling` as fallback. This plan implements the audit-log half only. Reasoning: `utmp`/`wtmp` are **binary** C-struct files whose layout (`struct utmpx`) is glibc/musl- and architecture-dependent and is not a documented stable ABI across the distro spread §4.3 targets — parsing it correctly requires either an FFI dependency or a hand-rolled struct layout this plan would be *guessing at*, which is exactly the bar Phase 1/2/3 refused to lower. `/proc/<pid>/loginuid` is a per-process attribute lookup, not an event source, and this dev machine has no `/proc`. The audit-log path, by contrast, is line-oriented UTF-8 text in the same auditd format two shipped sensors already parse, so it is portably implementable and fixture-testable here — the same test every prior phase applied. `SensorCapabilities.ebpf` stays `false`; `audit_fallback` is `true` when the configured log path exists (matching `ProcessExecSensor`'s exact capability shape).

3. **Telemetry scope is exactly seven `EventType`s, and no others are emitted anywhere in this phase.** §6's Identity row is a MINIMAL-tier sensor (the table in §6 does not list Identity separately; §4.3's "Telemetry level introduced" column says MINIMAL, i.e. session start/stop identity, not per-keystroke or per-syscall detail). This phase emits:
   - `SESSION_LOGIN` (from auditd `type=USER_LOGIN`)
   - `SESSION_LOGOUT` (from `type=USER_LOGOUT`)
   - `SESSION_CREATE` (from `type=USER_START`, i.e. PAM `session_open`)
   - `SESSION_TERMINATE` (from `type=USER_END`, i.e. PAM `session_close`)
   - `PRIVILEGE_UID_CHANGE` (from `type=SYSCALL syscall=105`, `setuid(2)` on x86_64)
   - `PRIVILEGE_GID_CHANGE` (from `type=SYSCALL syscall=106`, `setgid(2)` on x86_64)
   - `PRIVILEGE_SUDO` (from `type=USER_CMD`, the record sudo's audit integration writes)

   **Not emitted this phase, though present in the frozen `EventType` enum:** `PRIVILEGE_CAPABILITY_CHANGE` and `PRIVILEGE_SETUID`, plus `CAPABILITY_USE`/`LSM_DENIAL` from the `SECURITY` category. `PRIVILEGE_CAPABILITY_CHANGE` would come from `capset(2)`, whose audit record carries the capability bitmasks in fields whose exact names and encoding this plan is **not confident enough about to write authoritative fixture data for** (see Global Constraint #6) — and §4.3 places capability-use telemetry on the *Security (LSM/capabilities)* sensor row at DETAILED level, a different sensor and a later phase, not Identity at MINIMAL. `PRIVILEGE_SETUID` is deliberately left unemitted because its name is ambiguous between "the `setuid(2)` syscall was called" (already covered by `PRIVILEGE_UID_CHANGE`) and "a setuid-bit binary was executed" (a Process/Exec concern needing the file's mode bits, which `ProcessExecRaw` does not carry); emitting it under either reading would make the taxonomy ambiguous for every later consumer. Also not parsed: `setresuid(2)`/`setresgid(2)` — the three-argument variants sudo and many daemons actually use. Their x86_64 numbers (113/114) are stable, but their three-uid semantics (real/effective/saved, any of which may be `-1` meaning "unchanged") do not map onto a single `target_uid` without a policy decision this phase does not need to make: the `USER_CMD` record already gives us the sudo signal, and `setuid(2)` already gives us the single-argument transition. Adding 113/114 later is a two-line change to one `match` in `audit_record.rs` plus its tests.

4. **Privilege telemetry is emitted by the Identity Sensor, not by a separate crate — and this is a reading of the spec, verified, not an assumption.** §4.3's sensor catalog table has rows for Process/Exec, Filesystem, Network, DNS, Identity/Session, Systemd, Persistence, Kernel module, Container, Namespace, Cgroup, and Security (LSM/capabilities) — **there is no "Privilege" row**. §9.3's taxonomy nonetheless defines a full `PRIVILEGE:` category, and §26's trace attributes the session-start observation to "Identity Sensor (audit backend)". The only sensor in the catalog whose backend already observes `USER_*`, `USER_CMD` and `SYSCALL` records from the same audit stream is Identity. **Ruling: `osiris-sensors-identity` emits both `RawEvent::Identity` and `RawEvent::Privilege` from one `LineTailer` over one configured audit log.** Consequently the `provider` string on *both* canonical event families is `"identity_sensor/audit"` — the provider field names the emitting sensor+backend (§9.2), and there is no privilege sensor to name. This is documented in `normalize.rs`'s doc comments so a reader does not mistake it for a copy-paste error.

5. **Session attribution is best-effort, inherited by ppid, and its absence is never faked** (this phase's analogue of Phase 3's Global Constraint #5 pid-attribution disclosure). An auditd `USER_LOGIN`/`USER_START` record carries `ses=<n>`, the kernel audit session id, and `pid=` of the process that performed the login (typically `sshd`). Subsequent `PROCESS_EXEC` audit records also carry `ses=`, but Phase 1's `ProcessExecRaw` does **not** carry it, and widening `ProcessExecRaw` would ripple through Phase 1's parser, the generator, the pipeline and every existing test for no gain. Instead, the Enrich stage's new `SessionResolver` maps `pid → session_id` at login time and propagates it: when a non-identity event arrives for pid `P` with parent `PP`, the resolver returns `P`'s session if already known, else adopts `PP`'s session if `PP` is known, else returns `None`. **When it returns `None`, `CanonicalEvent.session` is left unset — never populated with a guessed or synthesized session id.** Consequences that are deliberate and disclosed:
   - A process that exec'd *before* the Agent observed the login (agent restart mid-session; a session opened before startup) has no session and gets no `TRIGGERED_BY_SESSION` edge. This mirrors `PROCESS_KEY_PROVISIONAL`'s existing "we did not observe it, so we do not claim it" discipline.
   - Events whose raw record carries no ppid at all (`NetworkEventRaw`, `DnsEventRaw` — neither has a `ppid` field) can only inherit a session if their own pid was already registered by that pid's own `PROCESS_EXEC`. In the normal case (a process execs, then connects) that is exactly what happens.
   - The resolver's `pid → session` map is *not* pruned on process exit (no `PROCESS_EXIT` event type is emitted by any sensor in this codebase yet). It **is** pruned wholesale on `SESSION_LOGOUT`/`SESSION_TERMINATE`, which removes the session record and every pid mapped to it — that is this phase's only bound on the map's growth, and it is disclosed as such in `SessionResolver`'s doc comment. A per-pid TTL/exit-driven eviction belongs with a real `PROCESS_EXIT` sensor, not here.

6. **`UserRef`'s `gid`/`euid`/`egid` are mirrored from `uid` when the backend does not report them, and such events are tagged `USER_REF_PARTIAL`.** `osiris_schema::UserRef` is frozen with `uid: u32, gid: u32, euid: u32, egid: u32` — all non-optional (verified against the current `crates/osiris-schema/src/entities.rs`). auditd's `type=SYSCALL` records **do** carry `uid=`, `gid=`, `euid=`, `egid=` separately, so `PRIVILEGE_UID_CHANGE`/`PRIVILEGE_GID_CHANGE` events populate all four for real. auditd's `USER_*` records carry only `uid=` and `auid=`. Rather than widen a frozen schema type for one call site (Phase 2's standing precedent: solve it in the consuming crate or defer, never widen frozen schema), the Normalize stage sets `gid`/`euid`/`egid` equal to the observed `uid` **and pushes the tag `USER_REF_PARTIAL` onto the event**, so no downstream consumer mistakes those three values for independently observed data. This is the same "tag rather than silently fabricate" mechanism `PROCESS_KEY_PROVISIONAL` already established in `enrich.rs`. Every task that constructs a canonical identity/privilege event must apply this rule through the single shared helper `normalize::build_user_ref` — never inline.

7. **`osiris-schema` needs zero changes — verified against the current source, not assumed.** Reading `crates/osiris-schema/src/` at commit `cdc722e` confirms all of the following already exist and are sufficient:
   - `event_type.rs`: `Category::Identity`, `Category::Privilege`; `EventType::{SessionLogin, SessionLogout, SessionCreate, SessionTerminate, PrivilegeUidChange, PrivilegeGidChange, PrivilegeCapabilityChange, PrivilegeSudo, PrivilegeSetuid}`; `EventType::category()` already maps all four `Session*` variants to `Category::Identity` and all five `Privilege*` variants to `Category::Privilege`. `Source::Audit` already exists (this phase must use `Source::Audit`, **not** `Source::Procfs` — see the New-workspace-facts note below about Phase 3's retrospective lesson).
   - `entities.rs`: `UserRef { uid, gid, euid, egid, username: Option<String>, loginuid: Option<u32> }` and `SessionRef { session_id: String, tty: Option<String>, remote_addr: Option<String>, auth_method: Option<String> }`.
   - `relationships.rs`: `EntityRef::User { host_id: Uuid, uid: u32 }`, `EntityRef::Session { session_id: String }`, `Relation::ExecutedAs`, `Relation::TriggeredBySession`. All four are currently **unused by any code in the workspace** — this phase is their first consumer.
   - `envelope.rs`: `CanonicalEvent` already has `user: Option<UserRef>` and `session: Option<SessionRef>` fields that no code has ever populated.

   Task 1 re-verifies this list against the live source before anything else is built. No task in this plan modifies `crates/osiris-schema/`.

8. **The Entity Graph edges this phase adds are exactly two, with precise attachment rules** (this phase's analogue of Phase 3's Global Constraint #8):
   - **`TRIGGERED_BY_SESSION`**: `from: EntityRef::Process { process_key }` → `to: EntityRef::Session { session_id }`. Attached on **`PROCESS_EXEC` events only**, and only when the Enrich stage actually resolved a session for that process. Not attached on file/network/DNS/privilege events even though they now carry a `session`: those events are attributable to a process that already carries the edge, so repeating it on every subsequent event would write the same fact hundreds of times per session (the same duplicate-fact reasoning that keeps `CONNECTED_TO` off `NETWORK_CLOSE`).
   - **`EXECUTED_AS`**: `from: EntityRef::Process { process_key }` → `to: EntityRef::User { host_id, uid: target_uid }`. Attached on **`PRIVILEGE_UID_CHANGE` events only**, and only when `event_data.target_uid` is present *and differs from* the acting `user.uid` (a `setuid(getuid())` no-op is not a privilege transition and must not mint an edge). Explicitly **not** attached on:
     - `PRIVILEGE_GID_CHANGE` — `EntityRef::User` is keyed by `(host_id, uid)`; there is no `EntityRef::Group`, and encoding a gid into a uid-keyed entity would corrupt the graph. The gid transition is still fully recorded in `event_data.target_gid`.
     - `PRIVILEGE_SUDO` — auditd's `type=USER_CMD` record does not reliably carry the target account across distributions (see Global Constraint #9); an edge citing an invented target uid is worse than no edge, the same rule Phase 2 applied to file identity and Phase 3 to unattributed connections.
     - `SESSION_LOGIN`/`SESSION_CREATE` — the frozen `Relation` enum has no variant naming "this session belongs to this user", and this phase does not extend it. The fact is carried losslessly by the event's own `user`/`session` fields.
   - No `Session → SPAWNED → Process` edge is written either, for the same frozen-enum reason (`SPAWNED` is already in use for process→process lineage from Phase 1's `parent_process` resolution; overloading it with a session-rooted meaning would make graph walks ambiguous).

9. **The auditd record formats this phase parses, and the exact confidence boundary.** Phase 1/2/3 held the bar "every audit/procfs format used was double-checked against real documented Linux behaviour." Holding it here means stating plainly what is standard and what is not:
   - **Confident, standard, and relied upon:** every auditd record line begins `type=<RECORD_TYPE> msg=audit(<secs>.<millis>:<serial>): ` followed by space-separated `key=value` pairs (this is exactly what `osiris_fileutil::parse_audit_msg_id` and the two shipped sensors already assume). The record types `USER_LOGIN`, `USER_LOGOUT`, `USER_START`, `USER_END`, `USER_CMD` and `SYSCALL` are all standard kernel/PAM audit record types. `USER_*` records carry outer fields `pid=`, `uid=`, `auid=`, `ses=` and a **nested, single-quoted** `msg='...'` sub-record holding fields such as `op=`, `acct=`, `exe=`, `hostname=`, `addr=`, `terminal=`, `res=` (and, for `USER_CMD`, `cwd=` and `cmd=`). `SYSCALL` records carry `arch=`, `syscall=`, `success=`, `exit=`, `a0=`..`a3=` (the syscall's first four arguments, lowercase hex, no `0x` prefix), `ppid=`, `pid=`, `auid=`, `uid=`, `gid=`, `euid=`, `egid=`, `ses=`, `comm=`, `exe=`. On x86_64, syscall 59 is `execve` and 322 is `execveat` (already relied upon by the shipped `osiris-sensors-process`), 105 is `setuid` and 106 is `setgid`.
   - **A real, load-bearing consequence of the nested `msg='...'`:** `osiris_fileutil::tokenize` returns a `HashMap`, so a `USER_*` line's *second* `msg=` (the single-quoted sub-record) overwrites the header's `msg=audit(...)` value. Feeding such a line to `tokenize` wholesale therefore loses the timestamp/serial. Task 3's parser must split the line into header / outer-body / inner-`msg` **before** tokenizing, and must never call `tokenize` on a whole `USER_*` line. `osiris-fileutil` itself is **not** modified: it is a leaf crate under the dependency-graph rule (`check_no_internal_deps osiris-fileutil`), its `tokenize` contract is correct for what it promises, and the header/inner split is Identity-record-specific knowledge that belongs in the sensor crate — exactly where `osiris-sensors-fs` already keeps its `PATH`-record hex-decoding.
   - **Explicitly NOT relied upon, and therefore not parsed:** the exact field name and encoding a `USER_CMD` record uses to report the *target* account (some sudo/audit builds emit no target on `USER_CMD` at all, relaying it instead through a following `CRED_ACQ`/`USER_START` record with `acct="root"`); the capability bitmask field names on `capset` syscall records; the value shape of `subj=` (SELinux context) fields; and the `key=` audit-rule tag, whose value is entirely operator-defined. Nothing in this plan's fixtures, parsers, tests or rules depends on any of those. Where a value is genuinely unknowable from the record, the corresponding field is `Option::None` and the plan says so at the field's definition — it is never filled with a plausible-looking invention.
   - **Also disclosed:** auditd writes `?` for an unknown `addr=`/`hostname=`/`terminal=` (e.g. a local console login has no remote address). Task 3's parser maps the literal `"?"` to `None` for those three fields, so `SessionRef.remote_addr == Some("?")` never occurs.

10. **The Identity Story route is `GET /api/v1/identity/story?session_id=…` or `?uid=…`** — carried from Phase 2's Global Constraint #12 and Phase 3's #10, same reasoning (§14.2's `/api/v1/users` listing and path-param story shapes presuppose a minted, stable resource id that does not exist before Phase 7's Investigation Engine; the query-param shape matches `osiris-api`'s existing `/api/v1/events`, `/api/v1/alerts`, `/api/v1/files/story` and `/api/v1/network/story`). The two lookup forms are **asymmetric, deliberately** (this phase's analogue of Phase 3's Global Constraint #9):
    - **`session_id` form:** every stored event whose `session.session_id` equals the given value — which, because Enrich attaches the session to *every* descendant event, is genuinely the whole multi-category story (identity + process + privilege + file + network) — time-ordered, plus every `Alert` whose evidence cites one of those events. This is precisely the "identity→process→file→network" chain §29's Phase 4 line calls for, assembled as a composed query over the existing `Storage::query`/`query_alerts` surface.
    - **`uid` form:** every stored event whose `user.uid` equals the given value, time-ordered, plus citing alerts. It does **not** expand to "…and everything in every session that user opened": that requires a second-pass fan-out (uid → session ids → all events in those sessions) whose cost is unbounded for a long-lived service account, and §12.3's general query planner that could express it cheaply is Phase 7 scope. An analyst who wants the session view starts from the session id, which the uid view itself surfaces on every returned event.
    - Neither form is a new Investigation Engine capability. `GET /api/v1/users` from §14.2's listing surface is **not** built — `GET /api/v1/events?event_type=SESSION_LOGIN` already serves that need genuinely, the same reasoning Phase 1 used to skip `/api/v1/files` and Phase 3 used to skip `/api/v1/network` and `/api/v1/dns`.

11. **`osiris-storage` gains two `QueryPlan` filters and `SqliteStorage` gains two indexed columns, via the same guarded additive migration Phase 2 and Phase 3 already established.** `session_id: Option<String>` (exact match on `session.session_id`) and `user_uid: Option<u32>` (exact match on `user.uid`). Both are added to the existing `events` table as nullable columns through the existing `for (column, ddl)` loop's `column_exists` guard plus `ALTER TABLE events ADD COLUMN` — non-destructive, idempotent, and O(1) metadata-only in SQLite. Pre-existing rows read back `NULL` and are **not** backfilled (identical to how Phase 2's `file_*` and Phase 3's `network_*`/`dns_domain` columns behaved) — which has no practical impact, since no database created before this phase can contain an event with a populated `session`/`user`.

12. **No Correlation Engine, no `BehavioralChain`, no stateful/windowed detection — verified against §29's Phase 6 line.** §29 places "Full Detection Engine (rule compiler, stateful sequence/window evaluation), **Correlation Engine graph-walk implementation**, Risk Engine weighted scoring, Baseline Engine frequency tables" in Phase 6. §11.3 defines `BehavioralChain` as "a graph walk over the entity graph (§9.4/§14.5) seeded from a trigger event". §29's Phase 4 line says this phase is "where the Correlation Engine's `BehavioralChain` first becomes genuinely multi-category" — read together with the Phase 6 line, that describes what becomes **possible** once the identity edges exist, not a mandate to build the walker now. **Ruling: this phase writes the edges and attaches sessions; it builds no chain type, no graph walker, no windowed rule evaluation, and no per-entity state table.** `osiris-detect` stays stateless single-event matching, exactly as Phase 2 built it and Phase 3 left it.

13. **No `osiris-detect` code changes; one new rule file.** `eval::field_value`'s dotted-JSON-path resolution already reaches `session.remote_addr`, `user.uid`, and `event_data.target_uid` on a serialized `CanonicalEvent` with no new code, and `engine::evaluate_rule` already treats a missing-or-null field as a non-match (verified in `crates/osiris-detect/src/engine.rs` — `let actual = field_value(event_json, &condition.field)?;` short-circuits the whole rule). `DetectionEngine::load_from_dir` already loads every `*.yaml`/`*.yml` in `config/rules/`, sorted, so a third rule file is picked up automatically. Task 6 verifies this against the actual current `eval.rs`/`engine.rs` rather than assuming it.

14. **No `osiris-server` changes and no `osiris-cli` changes.** Phase 2's Task 8 wired `DetectionEngine::evaluate_batch` into `run_ingestion_loop` generically, over every batch regardless of category; nothing about identity/privilege events needs different handling there. CLI verbs for identity/sessions are a Console/CLI-maturity concern for a later phase, matching Phase 2's and Phase 3's identical decisions (neither added a CLI verb for its own new Story endpoint).

15. **Dependency-graph boundary: one new line in `tools/check-dep-graph.sh`.** The new crate `osiris-sensors-identity` must never reach `osiris-server` or `osiris-api` (§18/§27's privilege boundary: the Agent side links sensors, the Server side never does). Task 3 adds `check_forbidden osiris-sensors-identity osiris-server osiris-api` alongside the three existing per-sensor lines. The existing generic `check_forbidden osiris-server osiris-sensors …` / `check_forbidden osiris-api osiris-sensors …` lines already cover the reverse direction. No existing check is relaxed.

None of these decisions touch the `CanonicalEvent` envelope's existing fields or the `EventType`/`Category`/`Severity`/`Source`/`Relation`/`EntityRef` enums (all already sufficient per Global Constraint #7).

**New workspace-wide facts this phase establishes** (binding on every task):

- Workspace `members` gains `"crates/osiris-sensors/identity"` (explicit path, matching `crates/osiris-sensors/process`, `.../fs`, `.../net` — `crates/osiris-sensors` itself is in `exclude`).
- New crate: `osiris-sensors-identity`. No new `[workspace.dependencies]` entries.
- **The `Source` for every event this phase emits is `Source::Audit`.** This is called out explicitly because Phase 3's retrospective recorded an implementer using `Source::Audit` for a `/proc`-polled sensor instead of the already-existing `Source::Procfs`. The full frozen `Source` enum is `{ Ebpf, Audit, Fanotify, Procfs, Dbus, ContainerApi, Synthetic }`; this phase's backend genuinely *is* Linux Audit, so `Audit` is correct, and `RawEventSource::Synthetic` maps to `Source::Synthetic` for generator-produced events exactly as it does for every existing category. Do not add a `Source` variant.
- The seven event types produced in this phase are `SESSION_LOGIN`, `SESSION_LOGOUT`, `SESSION_CREATE`, `SESSION_TERMINATE`, `PRIVILEGE_UID_CHANGE`, `PRIVILEGE_GID_CHANGE`, `PRIVILEGE_SUDO`, alongside Phase 1/2/3's `PROCESS_EXEC`/`FILE_*`/`NETWORK_*`/`DNS_QUERY`. No other `EventType` variant is produced anywhere.
- Every new **library** crate keeps Phase 0/1/2/3's discipline: zero `unwrap()`/`expect()` on I/O, lock, or parse results outside test code; return `Result` with a `thiserror` error type; recover poisoned mutexes via `unwrap_or_else(|p| p.into_inner())` rather than panicking.
- The third rule file lives at `config/rules/privilege_escalation_to_root_in_remote_session.yaml`, loaded by the same directory scan as the first two.
- Two new event tags exist workspace-wide: `USER_REF_PARTIAL` (Global Constraint #6), alongside the existing `PROCESS_KEY_PROVISIONAL` and `INVALID`.

---

### Task 1: `osiris-sensor-api` — `RawEvent::Identity` and `RawEvent::Privilege`

**Files:**
- Modify: `crates/osiris-sensor-api/src/raw_event.rs`
- Modify: `crates/osiris-sensor-api/src/lib.rs`

**Interfaces:**
- Consumes: nothing new. `osiris-sensor-api` has zero dependency on `osiris-schema` (verified: its `Cargo.toml` lists `serde`, `serde_json`, `async-trait`, `tokio`, `tokio-util`, `thiserror`, `osiris-health` only), so these raw types define their own small enums rather than reusing schema types — exactly as `FileOperation`, `NetworkOperation` and the raw `NetworkDirection` already do.
- Produces:
  - `osiris_sensor_api::IdentityOperation` — `enum { Login, Logout, SessionStart, SessionEnd }`.
  - `osiris_sensor_api::PrivilegeOperation` — `enum { UidChange, GidChange, Sudo }`.
  - `osiris_sensor_api::IdentityEventRaw` — the struct defined in Step 3.
  - `osiris_sensor_api::PrivilegeEventRaw` — the struct defined in Step 3.
  - `osiris_sensor_api::RawEvent::Identity(IdentityEventRaw)` and `RawEvent::Privilege(PrivilegeEventRaw)`.
  - `RawEvent::timestamp_ns(&self)` extended to cover both new variants.
  - Task 2's `normalize_identity_event`/`normalize_privilege_event`, Task 3's `osiris-sensors-identity` parser and Task 5's generator scenario all construct these two structs.

**Before writing any code**, open `crates/osiris-schema/src/event_type.rs`, `entities.rs` and `relationships.rs` and confirm Global Constraint #7's list item by item (`Category::Identity`, `Category::Privilege`, the four `Session*` and five `Privilege*` `EventType` variants and their `category()` mapping, `UserRef`, `SessionRef`, `EntityRef::User`, `EntityRef::Session`, `Relation::ExecutedAs`, `Relation::TriggeredBySession`, `Source::Audit`). If any is missing, **stop and report it** rather than adding it — this plan asserts zero schema changes and a gap would invalidate that assertion for every later task.

- [ ] **Step 1: Write the failing test for the new raw event shapes**

Append to the existing `#[cfg(test)] mod tests` block at the bottom of `crates/osiris-sensor-api/src/raw_event.rs`. Do not remove or modify any existing test in that block.

```rust
    fn identity_raw() -> IdentityEventRaw {
        IdentityEventRaw {
            operation: IdentityOperation::Login,
            session_id: "3".to_string(),
            pid: 1200,
            uid: 0,
            auid: Some(1000),
            username: Some("alice".to_string()),
            terminal: Some("/dev/pts/0".to_string()),
            remote_addr: Some("198.51.100.10".to_string()),
            auth_method: Some("sshd".to_string()),
            success: true,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: 1_690_000_000_123_000_000,
            audit_serial: Some(456),
            source: RawEventSource::Audit,
        }
    }

    fn privilege_raw() -> PrivilegeEventRaw {
        PrivilegeEventRaw {
            operation: PrivilegeOperation::UidChange,
            pid: 1400,
            ppid: 1300,
            uid: 1000,
            gid: Some(1000),
            euid: Some(1000),
            egid: Some(1000),
            auid: Some(1000),
            session_id: Some("3".to_string()),
            username: None,
            target_uid: Some(0),
            target_gid: None,
            command: None,
            success: true,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: 1_690_000_005_000_000_000,
            audit_serial: Some(470),
            source: RawEventSource::Audit,
        }
    }

    #[test]
    fn identity_raw_round_trips_through_json() {
        let raw = RawEvent::Identity(identity_raw());
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Identity(i) => {
                assert_eq!(i.operation, IdentityOperation::Login);
                assert_eq!(i.session_id, "3");
                assert_eq!(i.remote_addr.as_deref(), Some("198.51.100.10"));
                assert_eq!(i.auid, Some(1000));
            }
            other => panic!("expected RawEvent::Identity, got {other:?}"),
        }
    }

    #[test]
    fn privilege_raw_round_trips_through_json() {
        let raw = RawEvent::Privilege(privilege_raw());
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Privilege(p) => {
                assert_eq!(p.operation, PrivilegeOperation::UidChange);
                assert_eq!(p.target_uid, Some(0));
                assert_eq!(p.session_id.as_deref(), Some("3"));
                assert_eq!(p.euid, Some(1000));
            }
            other => panic!("expected RawEvent::Privilege, got {other:?}"),
        }
    }

    /// A local console login has no remote address and a sudo record often
    /// reports no target account (Global Constraint #9) — both must
    /// round-trip as `None`, never as a placeholder string.
    #[test]
    fn absent_optional_fields_round_trip_as_none() {
        let mut identity = identity_raw();
        identity.remote_addr = None;
        identity.username = None;
        let json = serde_json::to_string(&RawEvent::Identity(identity)).unwrap();
        match serde_json::from_str::<RawEvent>(&json).unwrap() {
            RawEvent::Identity(i) => {
                assert_eq!(i.remote_addr, None);
                assert_eq!(i.username, None);
            }
            other => panic!("expected RawEvent::Identity, got {other:?}"),
        }

        let mut privilege = privilege_raw();
        privilege.operation = PrivilegeOperation::Sudo;
        privilege.target_uid = None;
        privilege.command = Some("/usr/bin/whoami".to_string());
        let json = serde_json::to_string(&RawEvent::Privilege(privilege)).unwrap();
        match serde_json::from_str::<RawEvent>(&json).unwrap() {
            RawEvent::Privilege(p) => {
                assert_eq!(p.target_uid, None);
                assert_eq!(p.command.as_deref(), Some("/usr/bin/whoami"));
            }
            other => panic!("expected RawEvent::Privilege, got {other:?}"),
        }
    }

    #[test]
    fn timestamp_accessor_works_for_identity_and_privilege_variants() {
        assert_eq!(
            RawEvent::Identity(identity_raw()).timestamp_ns(),
            1_690_000_000_123_000_000
        );
        assert_eq!(
            RawEvent::Privilege(privilege_raw()).timestamp_ns(),
            1_690_000_005_000_000_000
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p osiris-sensor-api`
Expected: FAIL to compile — `cannot find type IdentityEventRaw`, `cannot find type PrivilegeEventRaw`, `no variant named Identity`, `no variant named Privilege`.

- [ ] **Step 3: Add the two raw shapes**

Insert into `crates/osiris-sensor-api/src/raw_event.rs`, immediately **before** the `pub enum RawEvent` declaration (after the existing `DnsEventRaw` struct):

```rust
/// The four session-lifecycle operations this phase emits — ARCHITECTURE.md
/// §9.3's whole `IDENTITY:` taxonomy row. Each maps 1:1 onto one standard
/// auditd record type (Phase 4a plan Global Constraints #3):
/// `Login` <- `type=USER_LOGIN`, `Logout` <- `type=USER_LOGOUT`,
/// `SessionStart` <- `type=USER_START` (PAM session_open),
/// `SessionEnd` <- `type=USER_END` (PAM session_close).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityOperation {
    Login,
    Logout,
    SessionStart,
    SessionEnd,
}

/// The three privilege transitions this phase emits (Phase 4a plan Global
/// Constraints #3). `UidChange` <- `type=SYSCALL syscall=105` (`setuid(2)`
/// on x86_64), `GidChange` <- `type=SYSCALL syscall=106` (`setgid(2)`),
/// `Sudo` <- `type=USER_CMD`. `setresuid`/`setresgid`/`capset` are
/// deliberately not parsed this phase — see the plan's Global Constraint #3
/// for why, and note that adding them is a `match`-arm change here plus one
/// in the sensor's parser, not a redesign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegeOperation {
    UidChange,
    GidChange,
    Sudo,
}

/// A session-lifecycle record, parsed from one auditd `USER_*` line.
///
/// Unlike `FileEventRaw`, this is assembled from a *single* record, not a
/// correlated group — but that record has two nested layers: outer
/// `key=value` pairs plus a single-quoted `msg='...'` sub-record. The
/// sensor's parser splits those before tokenizing (Phase 4a plan Global
/// Constraint #9); by the time this struct exists, both layers are merged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEventRaw {
    pub operation: IdentityOperation,
    /// The kernel audit session id, from the record's `ses=` field, kept as
    /// a string rather than an integer: it is an opaque correlation handle
    /// (§9.2's `SessionRef.session_id` is a string), auditd prints
    /// `ses=4294967295` for "no session", and a future non-audit backend
    /// (systemd-logind, utmp) may not produce integers at all.
    pub session_id: String,
    /// The pid that performed the login — `sshd`, `login`, `su`, etc. This
    /// is the process the Pipeline's `SessionResolver` roots the session's
    /// pid subtree at (plan Global Constraint #5).
    pub pid: u32,
    /// The record's own `uid=` — the uid of the *authenticating* process
    /// (usually 0 for sshd), not necessarily the user who logged in. The
    /// user who logged in is `auid`/`username`.
    pub uid: u32,
    /// The audit login uid, from `auid=`. `None` when the record omits it
    /// or prints the unset sentinel.
    pub auid: Option<u32>,
    /// From the nested `msg='... acct="alice" ...'`. `None` when absent —
    /// `USER_LOGIN` often carries `id=<uid>` instead of `acct=`.
    pub username: Option<String>,
    /// From the nested `terminal=`. `None` when the record printed `?`.
    pub terminal: Option<String>,
    /// From the nested `addr=`. `None` when the record printed `?` (a local
    /// console login has no remote address) — never the literal `"?"`.
    pub remote_addr: Option<String>,
    /// The authenticating program's file stem, derived from the nested
    /// `exe=` (e.g. `"sshd"`, `"login"`, `"su"`). This is what lands in
    /// §9.2's `SessionRef.auth_method`. `None` when `exe=` is absent.
    pub auth_method: Option<String>,
    /// From the nested `res=`: `res=success` -> true, anything else ->
    /// false. A failed login is still a real, storable event.
    pub success: bool,
    /// From the nested `exe=`, full path. Empty string when absent.
    pub exe_path: String,
    /// The basename of `exe_path` — `USER_*` records carry no `comm=`, so
    /// unlike `SYSCALL` records this is derived, not observed.
    pub comm: String,
    /// Wall-clock nanoseconds, UTC, from the audit event header.
    pub timestamp_ns: u64,
    /// The originating audit event's serial, retained for provenance so an
    /// operator can find the exact record in the source log.
    pub audit_serial: Option<u64>,
    pub source: RawEventSource,
}

/// A privilege-transition record.
///
/// `UidChange`/`GidChange` come from `type=SYSCALL` records, which carry
/// `gid=`/`euid=`/`egid=` — so those three are `Some` for them. `Sudo`
/// comes from `type=USER_CMD`, which carries only `uid=`/`auid=`/`ses=`, so
/// they are `None` there and the Normalize stage tags the resulting event
/// `USER_REF_PARTIAL` (plan Global Constraint #6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeEventRaw {
    pub operation: PrivilegeOperation,
    pub pid: u32,
    /// `0` for `Sudo`: `USER_CMD` records carry no `ppid=`. The Enrich
    /// stage treats ppid 0 as "no parent to inherit a session from", the
    /// same convention `normalize`'s existing `current_ppid` helper already
    /// uses for events whose `event_data` has no `ppid`.
    pub ppid: u32,
    /// The acting (real) uid *before* the transition.
    pub uid: u32,
    pub gid: Option<u32>,
    pub euid: Option<u32>,
    pub egid: Option<u32>,
    pub auid: Option<u32>,
    /// From `ses=`. `None` when the record omits it.
    pub session_id: Option<String>,
    /// The acting user's name when the record reports one. Always `None`
    /// for `SYSCALL`-derived records (audit does not resolve names).
    pub username: Option<String>,
    /// The uid being switched **to**, decoded from the `SYSCALL` record's
    /// `a0=` (setuid's first argument, lowercase hex). `None` for `Sudo`
    /// (plan Global Constraint #9: `USER_CMD` does not reliably report the
    /// target account) and `None` when `a0` decodes to `0xffffffff`, which
    /// is `(uid_t)-1`, i.e. "leave unchanged".
    pub target_uid: Option<u32>,
    /// The gid being switched **to**, decoded from `setgid`'s `a0=`. Same
    /// `-1` handling as `target_uid`. Always `None` for `UidChange`/`Sudo`.
    pub target_gid: Option<u32>,
    /// The command sudo was asked to run, hex-decoded from `USER_CMD`'s
    /// `cmd=` field. `None` for `SYSCALL`-derived records.
    pub command: Option<String>,
    /// `SYSCALL`'s `success=yes` or `USER_CMD`'s nested `res=success`.
    pub success: bool,
    pub exe_path: String,
    /// From `SYSCALL`'s `comm=`; the basename of `exe_path` for `Sudo`.
    pub comm: String,
    pub timestamp_ns: u64,
    pub audit_serial: Option<u64>,
    pub source: RawEventSource,
}
```

Then extend the `RawEvent` enum and its `timestamp_ns` accessor (replace the existing declaration and impl block wholesale with this):

```rust
/// The shape sensors emit onto their output channel (ARCHITECTURE.md §7.1
/// step 1, "Collect"). Phase 1 scoped this to Process/Exec; Phase 2 added
/// File; Phase 3 added Network and Dns; Phase 4a adds Identity and
/// Privilege.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RawEvent {
    ProcessExec(ProcessExecRaw),
    File(FileEventRaw),
    Network(NetworkEventRaw),
    Dns(DnsEventRaw),
    Identity(IdentityEventRaw),
    Privilege(PrivilegeEventRaw),
}

impl RawEvent {
    /// The originating backend's wall-clock timestamp, regardless of
    /// variant — used by sensors for their `last_event_at` health field
    /// without matching on the variant at every call site.
    pub fn timestamp_ns(&self) -> u64 {
        match self {
            RawEvent::ProcessExec(p) => p.timestamp_ns,
            RawEvent::File(f) => f.timestamp_ns,
            RawEvent::Network(n) => n.timestamp_ns,
            RawEvent::Dns(d) => d.timestamp_ns,
            RawEvent::Identity(i) => i.timestamp_ns,
            RawEvent::Privilege(p) => p.timestamp_ns,
        }
    }
}
```

- [ ] **Step 4: Re-export the new types**

Replace the `pub use raw_event::{...}` block in `crates/osiris-sensor-api/src/lib.rs` with:

```rust
pub use raw_event::{
    DnsEventRaw, FileEventRaw, FileOperation, IdentityEventRaw, IdentityOperation,
    NetworkDirection, NetworkEventRaw, NetworkOperation, PrivilegeEventRaw, PrivilegeOperation,
    ProcessExecRaw, RawEvent, RawEventSource,
};
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p osiris-sensor-api`
Expected: PASS — all existing tests plus the four new ones.

Then run `cargo build --workspace --all-targets` and expect it to **fail** in `osiris-pipeline` with a non-exhaustive-match error on `RawEvent` in `normalize`. That failure is the correct handoff into Task 2; do not silence it with a wildcard arm.

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-sensor-api
git commit -m "feat(sensor-api): RawEvent::Identity and RawEvent::Privilege

Two new raw shapes for the Phase 4a identity/privilege slice: session
lifecycle records (USER_LOGIN/LOGOUT/START/END) and privilege transitions
(setuid/setgid syscalls, USER_CMD sudo records). Optional fields are None
where the auditd record genuinely cannot report the value, never filled
with a placeholder (plan Global Constraint #9).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01CQ6yt1YUcRLAqQad8DthQc"
```

---

### Task 2: `osiris-pipeline` — the raw→canonical path, the `SessionResolver`, and the two entity edges

**Files:**
- Create: `crates/osiris-pipeline/src/session_resolver.rs`
- Modify: `crates/osiris-pipeline/src/normalize.rs`
- Modify: `crates/osiris-pipeline/src/enrich.rs`
- Modify: `crates/osiris-pipeline/src/validate.rs`
- Modify: `crates/osiris-pipeline/src/prioritize.rs`
- Modify: `crates/osiris-pipeline/src/pipeline.rs`
- Modify: `crates/osiris-pipeline/src/lib.rs`

**Interfaces:**
- Consumes (from Task 1): `osiris_sensor_api::{IdentityEventRaw, IdentityOperation, PrivilegeEventRaw, PrivilegeOperation, RawEvent::Identity, RawEvent::Privilege}` with exactly the field names listed in Task 1 Step 3.
- Produces:
  - `osiris_pipeline::session_resolver::SessionRecord` — `pub struct SessionRecord { pub session_id: String, pub uid: u32, pub username: Option<String>, pub tty: Option<String>, pub remote_addr: Option<String>, pub auth_method: Option<String> }` (derives `Debug, Clone`).
  - `osiris_pipeline::session_resolver::SessionResolver` with `pub fn new() -> Self`, `pub fn record_login(&mut self, pid: u32, record: SessionRecord)`, `pub fn attach(&mut self, pid: u32, ppid: u32) -> Option<String>`, `pub fn record_for(&self, session_id: &str) -> Option<&SessionRecord>`, `pub fn forget(&mut self, session_id: &str)`.
  - `osiris_pipeline::enrich` — **signature changes** to `pub fn enrich(event: CanonicalEvent, boot_id: &str, resolver: &mut ProcessResolver, sessions: &mut SessionResolver) -> CanonicalEvent`. The only non-test call site in the workspace is `crates/osiris-pipeline/src/pipeline.rs:44` (verified by grep); the compiler will point at it and at `enrich.rs`'s own tests.
  - `osiris_pipeline::normalize::build_user_ref(uid: u32, gid: Option<u32>, euid: Option<u32>, egid: Option<u32>, username: Option<String>, loginuid: Option<u32>) -> (osiris_schema::UserRef, bool)` — returns the ref and `true` when any of gid/euid/egid had to be mirrored from `uid` (Global Constraint #6). Crate-public so tests can assert on it.
  - `osiris_pipeline::lib` re-exports `SessionResolver` and `SessionRecord`.
  - Task 4's storage columns read `event.session.session_id` and `event.user.uid`, which this task is what populates. Task 6's rule reads `session.remote_addr` and `event_data.target_uid`. Task 7's Story endpoint depends on sessions being attached to *descendant* events, which is this task's `attach_session`.

- [ ] **Step 1: Write the failing test for the `SessionResolver`**

Create `crates/osiris-pipeline/src/session_resolver.rs` containing only this test module for now (the implementation lands in Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn ssh_session() -> SessionRecord {
        SessionRecord {
            session_id: "3".to_string(),
            uid: 0,
            username: Some("alice".to_string()),
            tty: Some("/dev/pts/0".to_string()),
            remote_addr: Some("198.51.100.10".to_string()),
            auth_method: Some("sshd".to_string()),
        }
    }

    #[test]
    fn a_logins_own_pid_resolves_to_its_session() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        assert_eq!(sessions.attach(100, 1), Some("3".to_string()));
    }

    #[test]
    fn a_child_inherits_its_parents_session() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        assert_eq!(sessions.attach(200, 100), Some("3".to_string()));
        // ...and a grandchild inherits it transitively, because attaching
        // pid 200 registered it as a session member.
        assert_eq!(sessions.attach(300, 200), Some("3".to_string()));
    }

    #[test]
    fn an_unrelated_pid_gets_no_session_rather_than_a_guess() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        assert_eq!(sessions.attach(999, 998), None);
        // A ppid of 0 (no parent reported) must never match anything.
        assert_eq!(sessions.attach(777, 0), None);
    }

    #[test]
    fn the_full_session_record_is_retrievable_by_id() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        let record = sessions.record_for("3").expect("session must be known");
        assert_eq!(record.remote_addr.as_deref(), Some("198.51.100.10"));
        assert_eq!(record.auth_method.as_deref(), Some("sshd"));
        assert_eq!(record.tty.as_deref(), Some("/dev/pts/0"));
        assert!(sessions.record_for("nope").is_none());
    }

    /// Logout is this phase's only bound on the pid map's growth (plan
    /// Global Constraint #5): forgetting a session must drop the record
    /// *and* every pid that mapped to it, or the map leaks for the life of
    /// the process.
    #[test]
    fn forgetting_a_session_drops_the_record_and_every_pid_mapped_to_it() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        assert_eq!(sessions.attach(200, 100), Some("3".to_string()));
        assert_eq!(sessions.attach(300, 200), Some("3".to_string()));

        sessions.forget("3");

        assert!(sessions.record_for("3").is_none());
        assert_eq!(sessions.attach(100, 1), None);
        assert_eq!(sessions.attach(200, 100), None);
        assert_eq!(sessions.attach(300, 200), None);
    }

    /// Two concurrent sessions must not bleed into each other.
    #[test]
    fn two_sessions_stay_independent() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        sessions.record_login(
            500,
            SessionRecord {
                session_id: "4".to_string(),
                uid: 0,
                username: Some("bob".to_string()),
                tty: Some("tty1".to_string()),
                remote_addr: None,
                auth_method: Some("login".to_string()),
            },
        );
        assert_eq!(sessions.attach(200, 100), Some("3".to_string()));
        assert_eq!(sessions.attach(600, 500), Some("4".to_string()));
        sessions.forget("3");
        assert_eq!(sessions.attach(600, 500), Some("4".to_string()));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Add `pub mod session_resolver;` to `crates/osiris-pipeline/src/lib.rs`, then run:

Run: `cargo test -p osiris-pipeline session_resolver`
Expected: FAIL to compile — `cannot find struct SessionResolver`, `cannot find struct SessionRecord`.

- [ ] **Step 3: Implement the `SessionResolver`**

Prepend to `crates/osiris-pipeline/src/session_resolver.rs` (above the test module written in Step 1):

```rust
use std::collections::HashMap;

/// Everything the Enrich stage needs to reconstruct a §9.2 `SessionRef`
/// (plus the session owner's uid) for any process that belongs to a
/// session, learned once from that session's `SESSION_LOGIN`/
/// `SESSION_CREATE` event.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub session_id: String,
    /// The uid reported by the login record itself — the authenticating
    /// process's uid (typically 0 for sshd), retained for completeness. It
    /// is deliberately NOT used to overwrite a descendant event's own
    /// `user`, which is that process's real uid.
    pub uid: u32,
    pub username: Option<String>,
    pub tty: Option<String>,
    pub remote_addr: Option<String>,
    pub auth_method: Option<String>,
}

/// In-memory pid→session resolver (ARCHITECTURE.md §4.2/§7.1 step 3, and
/// §26 step 3's "attach session_id from the Identity Sensor's earlier
/// SESSION_LOGIN … populated at login/exec time"). Sensors never
/// cross-reference each other; this single resolver in the Enrich stage is
/// where the identity↔process linkage is made, exactly as `ProcessResolver`
/// is where the pid↔process_key linkage is made.
///
/// KNOWN LIMITATION (bounded only by logout): `by_pid` grows one entry per
/// process that joins a session and is pruned only when that session ends
/// (`forget`), because no sensor in this codebase emits `PROCESS_EXIT` yet
/// (Phase 4a plan Global Constraint #5). A long-lived session that spawns
/// very many short-lived processes therefore accumulates entries until it
/// logs out. Per-pid eviction belongs with a real process-exit sensor.
#[derive(Default)]
pub struct SessionResolver {
    by_pid: HashMap<u32, String>,
    sessions: HashMap<String, SessionRecord>,
    /// Reverse index so `forget` is O(members) rather than a full scan of
    /// `by_pid` — the map can hold many thousands of pids across many
    /// sessions, and logouts are common.
    members: HashMap<String, Vec<u32>>,
}

impl SessionResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `pid` (the process that performed the login — sshd,
    /// login, su) is the root of `record`'s session. A repeated login for
    /// the same session id replaces the record and re-roots it at the new
    /// pid, without discarding members already attached to that session.
    pub fn record_login(&mut self, pid: u32, record: SessionRecord) {
        let session_id = record.session_id.clone();
        self.sessions.insert(session_id.clone(), record);
        self.by_pid.insert(pid, session_id.clone());
        self.members.entry(session_id).or_default().push(pid);
    }

    /// Resolves `pid`'s session, adopting its parent's session if `pid` is
    /// not itself known. Returns `None` — never a guess — when neither the
    /// pid nor its parent belongs to a known session (plan Global
    /// Constraint #5). A `ppid` of `0` never matches: `0` is the
    /// "no parent reported" convention used by `event_data`'s `ppid`
    /// fallback and by `PrivilegeEventRaw.ppid` for `USER_CMD` records.
    pub fn attach(&mut self, pid: u32, ppid: u32) -> Option<String> {
        if let Some(session_id) = self.by_pid.get(&pid) {
            return Some(session_id.clone());
        }
        if ppid == 0 {
            return None;
        }
        let session_id = self.by_pid.get(&ppid)?.clone();
        self.by_pid.insert(pid, session_id.clone());
        self.members
            .entry(session_id.clone())
            .or_default()
            .push(pid);
        Some(session_id)
    }

    pub fn record_for(&self, session_id: &str) -> Option<&SessionRecord> {
        self.sessions.get(session_id)
    }

    /// Drops a session and every pid mapped to it (called on
    /// `SESSION_LOGOUT`/`SESSION_TERMINATE`). A pid that outlives its
    /// session — a daemon deliberately detached from the login — stops
    /// being attributed to it, which is the correct answer: the session is
    /// over.
    pub fn forget(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
        if let Some(pids) = self.members.remove(session_id) {
            for pid in pids {
                // Only remove the mapping if it still points at this
                // session — a pid re-attached to a newer session must not
                // be dropped by an older session's logout.
                if self.by_pid.get(&pid).map(String::as_str) == Some(session_id) {
                    self.by_pid.remove(&pid);
                }
            }
        }
    }
}
```

- [ ] **Step 4: Run the resolver tests to verify they pass**

Run: `cargo test -p osiris-pipeline session_resolver`
Expected: PASS — all six tests.

- [ ] **Step 5: Write the failing tests for identity/privilege normalization**

Append to the existing `#[cfg(test)] mod tests` block in `crates/osiris-pipeline/src/normalize.rs`:

```rust
    fn identity_raw(operation: osiris_sensor_api::IdentityOperation) -> RawEvent {
        RawEvent::Identity(osiris_sensor_api::IdentityEventRaw {
            operation,
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
            timestamp_ns: 1_690_000_000_123_000_000,
            audit_serial: Some(456),
            source: RawEventSource::Audit,
        })
    }

    #[test]
    fn identity_operations_map_to_the_matching_event_type_and_identity_category() {
        use osiris_sensor_api::IdentityOperation;
        let host = sample_host();
        for (operation, expected) in [
            (IdentityOperation::Login, EventType::SessionLogin),
            (IdentityOperation::Logout, EventType::SessionLogout),
            (IdentityOperation::SessionStart, EventType::SessionCreate),
            (IdentityOperation::SessionEnd, EventType::SessionTerminate),
        ] {
            let event = normalize(identity_raw(operation), &host, "boot-1");
            assert_eq!(event.event_type, expected);
            assert_eq!(event.category, Category::Identity);
            assert_eq!(event.source, Source::Audit);
            assert_eq!(event.provider, "identity_sensor/audit");
        }
    }

    #[test]
    fn identity_event_populates_session_and_user_refs() {
        use osiris_sensor_api::IdentityOperation;
        let host = sample_host();
        let event = normalize(identity_raw(IdentityOperation::Login), &host, "boot-1");

        let session = event.session.as_ref().expect("session must be populated");
        assert_eq!(session.session_id, "3");
        assert_eq!(session.tty.as_deref(), Some("/dev/pts/0"));
        assert_eq!(session.remote_addr.as_deref(), Some("198.51.100.10"));
        assert_eq!(session.auth_method.as_deref(), Some("sshd"));

        let user = event.user.as_ref().expect("user must be populated");
        assert_eq!(user.uid, 0);
        assert_eq!(user.username.as_deref(), Some("alice"));
        assert_eq!(user.loginuid, Some(1000));

        // A USER_* record reports no gid/euid/egid, so those are mirrored
        // from uid and the event is tagged (plan Global Constraint #6).
        assert_eq!((user.gid, user.euid, user.egid), (0, 0, 0));
        assert!(event.tags.contains(&"USER_REF_PARTIAL".to_string()));

        // The login process itself is still an actor with a pid.
        assert_eq!(event.process.as_ref().unwrap().pid, 100);
        assert_eq!(event.process.as_ref().unwrap().exe_path, "/usr/sbin/sshd");
    }

    fn privilege_raw(
        operation: osiris_sensor_api::PrivilegeOperation,
        target_uid: Option<u32>,
        target_gid: Option<u32>,
    ) -> RawEvent {
        RawEvent::Privilege(osiris_sensor_api::PrivilegeEventRaw {
            operation,
            pid: 300,
            ppid: 200,
            uid: 1000,
            gid: Some(1000),
            euid: Some(1000),
            egid: Some(1000),
            auid: Some(1000),
            session_id: Some("3".to_string()),
            username: None,
            target_uid,
            target_gid,
            command: None,
            success: true,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: 1_690_000_005_000_000_000,
            audit_serial: Some(470),
            source: RawEventSource::Audit,
        })
    }

    #[test]
    fn privilege_operations_map_to_the_matching_event_type_and_privilege_category() {
        use osiris_sensor_api::PrivilegeOperation;
        let host = sample_host();
        for (operation, expected) in [
            (PrivilegeOperation::UidChange, EventType::PrivilegeUidChange),
            (PrivilegeOperation::GidChange, EventType::PrivilegeGidChange),
            (PrivilegeOperation::Sudo, EventType::PrivilegeSudo),
        ] {
            let event = normalize(privilege_raw(operation, Some(0), None), &host, "boot-1");
            assert_eq!(event.event_type, expected);
            assert_eq!(event.category, Category::Privilege);
            assert_eq!(event.provider, "identity_sensor/audit");
        }
    }

    /// A SYSCALL-derived privilege record reports gid/euid/egid for real,
    /// so it must NOT be tagged partial — that tag is reserved for the
    /// USER_* records that genuinely cannot report them.
    #[test]
    fn syscall_derived_privilege_event_has_a_complete_user_ref_and_no_partial_tag() {
        use osiris_sensor_api::PrivilegeOperation;
        let host = sample_host();
        let event = normalize(
            privilege_raw(PrivilegeOperation::UidChange, Some(0), None),
            &host,
            "boot-1",
        );
        let user = event.user.as_ref().expect("user must be populated");
        assert_eq!((user.uid, user.gid, user.euid, user.egid), (1000, 1000, 1000, 1000));
        assert!(!event.tags.contains(&"USER_REF_PARTIAL".to_string()));
        assert_eq!(event.event_data["target_uid"], serde_json::json!(0));
        assert_eq!(event.event_data["ppid"], serde_json::json!(200));
    }

    #[test]
    fn a_sudo_record_without_gid_fields_is_tagged_partial() {
        use osiris_sensor_api::{PrivilegeEventRaw, PrivilegeOperation};
        let host = sample_host();
        let raw = RawEvent::Privilege(PrivilegeEventRaw {
            operation: PrivilegeOperation::Sudo,
            pid: 300,
            ppid: 0,
            uid: 1000,
            gid: None,
            euid: None,
            egid: None,
            auid: Some(1000),
            session_id: Some("3".to_string()),
            username: None,
            target_uid: None,
            target_gid: None,
            command: Some("/usr/bin/whoami".to_string()),
            success: true,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: 1_690_000_004_000_000_000,
            audit_serial: Some(469),
            source: RawEventSource::Audit,
        });
        let event = normalize(raw, &host, "boot-1");
        assert_eq!(event.event_type, EventType::PrivilegeSudo);
        assert!(event.tags.contains(&"USER_REF_PARTIAL".to_string()));
        assert_eq!(
            event.event_data["command"],
            serde_json::json!("/usr/bin/whoami")
        );
        assert!(event.event_data["target_uid"].is_null());
    }

    /// The session id a privilege record carries is enough to populate a
    /// minimal `SessionRef` right at Normalize time; Enrich later replaces
    /// it with the fuller record (tty/remote_addr/auth_method) when the
    /// session's login was observed.
    #[test]
    fn privilege_event_carries_a_minimal_session_ref_from_its_own_ses_field() {
        use osiris_sensor_api::PrivilegeOperation;
        let host = sample_host();
        let event = normalize(
            privilege_raw(PrivilegeOperation::UidChange, Some(0), None),
            &host,
            "boot-1",
        );
        let session = event.session.as_ref().expect("session must be populated");
        assert_eq!(session.session_id, "3");
        assert_eq!(session.remote_addr, None);
    }
```

- [ ] **Step 6: Run the normalize tests to verify they fail**

Run: `cargo test -p osiris-pipeline normalize`
Expected: FAIL to compile — non-exhaustive `match raw` in `normalize`, plus `cannot find function normalize_identity_event`.

- [ ] **Step 7: Implement identity/privilege normalization**

In `crates/osiris-pipeline/src/normalize.rs`, extend the `use` block at the top:

```rust
use osiris_schema::{
    CanonicalEvent, Category, DnsRef, EventType, FileRef, HostRef, NetworkDirection, NetworkRef,
    ProcessKey, ProcessRef, SessionRef, Severity, Source, UserRef, SCHEMA_VERSION,
};
use osiris_sensor_api::{
    DnsEventRaw, FileEventRaw, FileOperation, IdentityEventRaw, IdentityOperation,
    NetworkDirection as RawNetworkDirection, NetworkEventRaw, NetworkOperation, PrivilegeEventRaw,
    PrivilegeOperation, ProcessExecRaw, RawEvent, RawEventSource,
};
```

Extend the top-level dispatch:

```rust
pub fn normalize(raw: RawEvent, host: &HostRef, boot_id: &str) -> CanonicalEvent {
    match raw {
        RawEvent::ProcessExec(p) => normalize_process_exec(p, host, boot_id),
        RawEvent::File(f) => normalize_file_event(f, host, boot_id),
        RawEvent::Network(n) => normalize_network_event(n, host, boot_id),
        RawEvent::Dns(d) => normalize_dns_event(d, host, boot_id),
        RawEvent::Identity(i) => normalize_identity_event(i, host, boot_id),
        RawEvent::Privilege(p) => normalize_privilege_event(p, host, boot_id),
    }
}
```

Append these functions to the same file, after `normalize_dns_event`:

```rust
/// Builds a §9.2 `UserRef` from what the backend actually reported.
///
/// `UserRef`'s `gid`/`euid`/`egid` are non-optional in the frozen schema
/// (Phase 0), but auditd's `USER_*` records report only `uid=`. Rather than
/// widen a frozen schema type for one call site (Phase 2's standing
/// precedent), the missing three are mirrored from `uid` and the caller is
/// told so via the returned `bool`, which becomes the `USER_REF_PARTIAL`
/// tag (Phase 4a plan Global Constraint #6). Nothing downstream may treat
/// those three as observed values on a tagged event.
pub fn build_user_ref(
    uid: u32,
    gid: Option<u32>,
    euid: Option<u32>,
    egid: Option<u32>,
    username: Option<String>,
    loginuid: Option<u32>,
) -> (UserRef, bool) {
    let partial = gid.is_none() || euid.is_none() || egid.is_none();
    (
        UserRef {
            uid,
            gid: gid.unwrap_or(uid),
            euid: euid.unwrap_or(uid),
            egid: egid.unwrap_or(uid),
            username,
            loginuid,
        },
        partial,
    )
}

/// ARCHITECTURE.md §4.3 has no "Privilege" sensor row — privilege
/// telemetry is emitted by whichever sensor observes the transition, which
/// for this codebase is the Identity sensor's audit backend (it already
/// tails the log carrying `SYSCALL` and `USER_CMD` records). Both identity
/// and privilege events therefore name that one sensor in `provider`
/// (Phase 4a plan Global Constraint #4); this is deliberate, not a
/// copy-paste error.
fn identity_provider(source: RawEventSource) -> &'static str {
    match source {
        RawEventSource::Audit => "identity_sensor/audit",
        RawEventSource::Synthetic => "identity_sensor/synthetic",
        // No identity/privilege backend uses procfs polling in this
        // codebase (the `/proc/<pid>/loginuid` path from §4.3 is a lookup,
        // not an event source — plan Global Constraint #2); handled for
        // match exhaustiveness only.
        RawEventSource::Procfs => "identity_sensor/procfs",
    }
}

fn schema_source(source: RawEventSource) -> Source {
    match source {
        RawEventSource::Audit => Source::Audit,
        RawEventSource::Synthetic => Source::Synthetic,
        RawEventSource::Procfs => Source::Procfs,
    }
}

fn normalize_identity_event(
    raw: IdentityEventRaw,
    host: &HostRef,
    boot_id: &str,
) -> CanonicalEvent {
    let event_type = match raw.operation {
        IdentityOperation::Login => EventType::SessionLogin,
        IdentityOperation::Logout => EventType::SessionLogout,
        IdentityOperation::SessionStart => EventType::SessionCreate,
        IdentityOperation::SessionEnd => EventType::SessionTerminate,
    };
    let (user, partial) = build_user_ref(
        raw.uid,
        None,
        None,
        None,
        raw.username.clone(),
        raw.auid,
    );
    let mut tags = Vec::new();
    if partial {
        tags.push("USER_REF_PARTIAL".to_string());
    }
    let process = provisional_process(Some(raw.pid), &raw.exe_path, host.host_id, boot_id);
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host.host_id,
        boot_id: boot_id.to_string(),
        timestamp: raw.timestamp_ns,
        monotonic_timestamp: raw.timestamp_ns,
        event_type,
        category: Category::Identity,
        severity: Severity::Info,
        host: host.clone(),
        user: Some(user),
        session: Some(SessionRef {
            session_id: raw.session_id,
            tty: raw.terminal,
            remote_addr: raw.remote_addr,
            auth_method: raw.auth_method,
        }),
        process,
        parent_process: None,
        thread: None,
        file: None,
        network: None,
        dns: None,
        device: None,
        service: None,
        container: None,
        namespace: None,
        cgroup: None,
        kernel: None,
        source: schema_source(raw.source),
        provider: identity_provider(raw.source).to_string(),
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

fn normalize_privilege_event(
    raw: PrivilegeEventRaw,
    host: &HostRef,
    boot_id: &str,
) -> CanonicalEvent {
    let event_type = match raw.operation {
        PrivilegeOperation::UidChange => EventType::PrivilegeUidChange,
        PrivilegeOperation::GidChange => EventType::PrivilegeGidChange,
        PrivilegeOperation::Sudo => EventType::PrivilegeSudo,
    };
    let (user, partial) = build_user_ref(
        raw.uid,
        raw.gid,
        raw.euid,
        raw.egid,
        raw.username.clone(),
        raw.auid,
    );
    let mut tags = Vec::new();
    if partial {
        tags.push("USER_REF_PARTIAL".to_string());
    }
    // A minimal SessionRef from the record's own `ses=`. The Enrich stage
    // replaces it with the fuller record (tty/remote_addr/auth_method) when
    // that session's login was observed; leaving it minimal here means a
    // privilege event is still session-attributed even if the login
    // happened before the Agent started.
    let session = raw.session_id.clone().map(|session_id| SessionRef {
        session_id,
        tty: None,
        remote_addr: None,
        auth_method: None,
    });
    let process = provisional_process(Some(raw.pid), &raw.exe_path, host.host_id, boot_id);
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host.host_id,
        boot_id: boot_id.to_string(),
        timestamp: raw.timestamp_ns,
        monotonic_timestamp: raw.timestamp_ns,
        event_type,
        category: Category::Privilege,
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
        service: None,
        container: None,
        namespace: None,
        cgroup: None,
        kernel: None,
        source: schema_source(raw.source),
        provider: identity_provider(raw.source).to_string(),
        raw_event: None,
        relationships: vec![],
        tags,
        risk: None,
        event_data: serde_json::json!({
            "comm": raw.comm,
            "ppid": raw.ppid,
            "uid": raw.uid,
            "auid": raw.auid,
            "target_uid": raw.target_uid,
            "target_gid": raw.target_gid,
            "command": raw.command,
            "success": raw.success,
            "audit_serial": raw.audit_serial,
        }),
    }
}
```

- [ ] **Step 8: Run the normalize tests to verify they pass**

Run: `cargo test -p osiris-pipeline normalize`
Expected: PASS — all existing normalize tests plus the six new ones.

- [ ] **Step 9: Write the failing tests for session attachment and the two edges**

Append to the existing `#[cfg(test)] mod tests` block in `crates/osiris-pipeline/src/enrich.rs`. First update the two existing helper-using tests' call shape — every existing call `enrich(event, "boot-1", &mut resolver)` in this module becomes `enrich(event, "boot-1", &mut resolver, &mut sessions)` with a `let mut sessions = SessionResolver::new();` alongside each existing `let mut resolver = ProcessResolver::new();`. The compiler lists every site; make the change mechanically and change nothing else about those tests.

Then append:

```rust
    use crate::session_resolver::{SessionRecord, SessionResolver};
    use osiris_schema::{SessionRef, UserRef};

    fn login_event(host_id: uuid::Uuid, pid: u32) -> CanonicalEvent {
        let mut event = bare_event(host_id, pid, 1);
        event.event_type = EventType::SessionLogin;
        event.category = Category::Identity;
        event.session = Some(SessionRef {
            session_id: "3".to_string(),
            tty: Some("/dev/pts/0".to_string()),
            remote_addr: Some("198.51.100.10".to_string()),
            auth_method: Some("sshd".to_string()),
        });
        event.user = Some(UserRef {
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            username: Some("alice".to_string()),
            loginuid: Some(1000),
        });
        event
    }

    fn privilege_event(
        host_id: uuid::Uuid,
        pid: u32,
        ppid: u32,
        acting_uid: u32,
        target_uid: Option<u32>,
    ) -> CanonicalEvent {
        let mut event = bare_event(host_id, pid, ppid);
        event.event_type = EventType::PrivilegeUidChange;
        event.category = Category::Privilege;
        event.user = Some(UserRef {
            uid: acting_uid,
            gid: acting_uid,
            euid: acting_uid,
            egid: acting_uid,
            username: None,
            loginuid: Some(1000),
        });
        event.event_data = serde_json::json!({ "ppid": ppid, "target_uid": target_uid });
        event
    }

    #[test]
    fn a_process_execed_inside_a_session_inherits_that_session() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();

        let _sshd = enrich(bare_event(host_id, 100, 1), "boot-1", &mut resolver, &mut sessions);
        let _login = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        let bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);
        let curl = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver, &mut sessions);

        for (name, event) in [("bash", &bash), ("curl", &curl)] {
            let session = event
                .session
                .as_ref()
                .unwrap_or_else(|| panic!("{name} must inherit the SSH session"));
            assert_eq!(session.session_id, "3");
            assert_eq!(session.remote_addr.as_deref(), Some("198.51.100.10"));
            assert_eq!(session.auth_method.as_deref(), Some("sshd"));
        }
    }

    #[test]
    fn a_process_outside_any_session_gets_no_session_rather_than_a_guess() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let _login = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        let cron = enrich(bare_event(host_id, 900, 1), "boot-1", &mut resolver, &mut sessions);
        assert!(cron.session.is_none());
    }

    /// ARCHITECTURE.md §9.4 + plan Global Constraint #8: the edge is
    /// written once, on the PROCESS_EXEC event, and cites the authoritative
    /// process key.
    #[test]
    fn a_process_exec_inside_a_session_gains_a_triggered_by_session_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let _login = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        let bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);

        let edges: Vec<_> = bash
            .relationships
            .iter()
            .filter(|r| r.relation == Relation::TriggeredBySession)
            .collect();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].event_id, bash.event_id);
        match (&edges[0].from, &edges[0].to) {
            (
                osiris_schema::EntityRef::Process { process_key },
                osiris_schema::EntityRef::Session { session_id },
            ) => {
                assert_eq!(*process_key, bash.process.as_ref().unwrap().process_key);
                assert_eq!(session_id, "3");
            }
            other => panic!("expected a Process -> Session edge, got {other:?}"),
        }
    }

    #[test]
    fn a_process_exec_outside_a_session_gains_no_triggered_by_session_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let cron = enrich(bare_event(host_id, 900, 1), "boot-1", &mut resolver, &mut sessions);
        assert!(cron
            .relationships
            .iter()
            .all(|r| r.relation != Relation::TriggeredBySession));
    }

    #[test]
    fn a_real_uid_escalation_gains_an_executed_as_edge_to_the_target_user() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let _login = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        let _bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);
        let sudo = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver, &mut sessions);
        let escalation = enrich(
            privilege_event(host_id, 300, 200, 1000, Some(0)),
            "boot-1",
            &mut resolver,
            &mut sessions,
        );

        let edges: Vec<_> = escalation
            .relationships
            .iter()
            .filter(|r| r.relation == Relation::ExecutedAs)
            .collect();
        assert_eq!(edges.len(), 1);
        match (&edges[0].from, &edges[0].to) {
            (
                osiris_schema::EntityRef::Process { process_key },
                osiris_schema::EntityRef::User {
                    host_id: edge_host,
                    uid,
                },
            ) => {
                assert_eq!(*process_key, sudo.process.as_ref().unwrap().process_key);
                assert_eq!(*edge_host, host_id);
                assert_eq!(*uid, 0);
            }
            other => panic!("expected a Process -> User edge, got {other:?}"),
        }
        // The privilege event also inherits the session, which is what
        // makes Task 6's rule able to require a remote session.
        assert_eq!(
            escalation.session.as_ref().unwrap().remote_addr.as_deref(),
            Some("198.51.100.10")
        );
    }

    /// setuid(getuid()) is a no-op, not a privilege transition — minting an
    /// edge for it would fill the graph with self-loops (plan Global
    /// Constraint #8).
    #[test]
    fn a_uid_change_to_the_same_uid_gains_no_executed_as_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let event = enrich(
            privilege_event(host_id, 300, 200, 1000, Some(1000)),
            "boot-1",
            &mut resolver,
            &mut sessions,
        );
        assert!(event
            .relationships
            .iter()
            .all(|r| r.relation != Relation::ExecutedAs));
    }

    /// A sudo record with no reported target account (plan Global
    /// Constraint #9) must produce no edge rather than an invented one.
    #[test]
    fn a_privilege_event_without_a_target_uid_gains_no_executed_as_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let mut event = privilege_event(host_id, 300, 200, 1000, None);
        event.event_type = EventType::PrivilegeSudo;
        let event = enrich(event, "boot-1", &mut resolver, &mut sessions);
        assert!(event
            .relationships
            .iter()
            .all(|r| r.relation != Relation::ExecutedAs));
    }

    /// Logout ends the session: a process that execs afterwards must not be
    /// attributed to it.
    #[test]
    fn a_logout_stops_further_processes_being_attributed_to_the_session() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let _login = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        let bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);
        assert!(bash.session.is_some());

        let mut logout = login_event(host_id, 100);
        logout.event_type = EventType::SessionLogout;
        let _logout = enrich(logout, "boot-1", &mut resolver, &mut sessions);

        let after = enrich(bare_event(host_id, 400, 100), "boot-1", &mut resolver, &mut sessions);
        assert!(after.session.is_none());
    }
```

- [ ] **Step 10: Run the enrich tests to verify they fail**

Run: `cargo test -p osiris-pipeline enrich`
Expected: FAIL to compile — `enrich` takes 3 arguments but 4 were supplied.

- [ ] **Step 11: Implement session attachment and the two edges**

In `crates/osiris-pipeline/src/enrich.rs`, replace the `use` block and the `enrich` function with:

```rust
use osiris_schema::{
    CanonicalEvent, Category, EntityRef, EntityRelationship, EventType, FileIdentity, ProcessRef,
    Relation, SessionRef,
};

use crate::process_resolver::ProcessResolver;
use crate::session_resolver::{SessionRecord, SessionResolver};

/// Enrich (local) stage (ARCHITECTURE.md §7.1 step 3): attach host/boot
/// identity, resolve process identity via the Process Resolver, attach
/// session identity via the Session Resolver (§26 step 3), and compute the
/// entity-graph edges §9.4 requires be written once here rather than
/// re-derived by every consumer. Cheap, always-available context only —
/// expensive enrichment is server-side (§7.2's split is preserved by simply
/// not doing that work yet, not by doing it here).
pub fn enrich(
    mut event: CanonicalEvent,
    boot_id: &str,
    resolver: &mut ProcessResolver,
    sessions: &mut SessionResolver,
) -> CanonicalEvent {
    event.boot_id = boot_id.to_string();

    match event.category {
        // Process events are the *source* of process identity: Normalize
        // hashed the real start time into their process_key, and they
        // populate the resolver for everyone else.
        Category::Process => enrich_process_event(&mut event, resolver),
        // Every other category *consumes* identity: the pid is known but
        // the start time isn't, so Normalize could only mint a provisional
        // key. Replace it with the authoritative one where we have it.
        _ => enrich_non_process_event(&mut event, resolver),
    }

    attach_session(&mut event, sessions);

    match event.category {
        Category::File => attach_file_relationship(&mut event),
        Category::Network => attach_network_relationship(&mut event),
        Category::Dns => attach_dns_relationships(&mut event),
        Category::Process => attach_session_relationship(&mut event),
        Category::Privilege => attach_executed_as_relationship(&mut event),
        _ => {}
    }

    event
}

/// §26 step 3's session linkage, in both directions:
///
/// * An IDENTITY event is the *source* of session identity — Normalize
///   already populated its `session`/`user` from the record itself, so here
///   it only teaches (or un-teaches) the resolver.
/// * Every other event *consumes* it: its pid, or its parent's pid, may
///   belong to a known session, in which case the full `SessionRef` is
///   attached. When neither does, `session` is left exactly as Normalize
///   produced it — `None` for most categories, and the minimal
///   `ses=`-derived ref for privilege events (plan Global Constraint #5:
///   never a guessed session id).
fn attach_session(event: &mut CanonicalEvent, sessions: &mut SessionResolver) {
    if event.category == Category::Identity {
        let (Some(session), Some(process)) = (event.session.clone(), event.process.as_ref())
        else {
            return;
        };
        match event.event_type {
            EventType::SessionLogin | EventType::SessionCreate => {
                sessions.record_login(
                    process.pid,
                    SessionRecord {
                        session_id: session.session_id.clone(),
                        uid: event.user.as_ref().map(|u| u.uid).unwrap_or(0),
                        username: event.user.as_ref().and_then(|u| u.username.clone()),
                        tty: session.tty.clone(),
                        remote_addr: session.remote_addr.clone(),
                        auth_method: session.auth_method.clone(),
                    },
                );
            }
            EventType::SessionLogout | EventType::SessionTerminate => {
                sessions.forget(&session.session_id);
            }
            _ => {}
        }
        return;
    }

    let Some(pid) = event.process.as_ref().map(|p| p.pid) else {
        return;
    };
    let ppid = current_ppid(event);
    let Some(session_id) = sessions.attach(pid, ppid) else {
        return;
    };
    let Some(record) = sessions.record_for(&session_id) else {
        return;
    };
    event.session = Some(SessionRef {
        session_id: record.session_id.clone(),
        tty: record.tty.clone(),
        remote_addr: record.remote_addr.clone(),
        auth_method: record.auth_method.clone(),
    });
}

/// Writes the §9.4 `Process -TRIGGERED_BY_SESSION-> Session` edge (plan
/// Global Constraint #8). Only on `PROCESS_EXEC`: every later event from
/// that process carries the same session, so repeating the edge on each of
/// them would write one fact hundreds of times per session — the same
/// duplicate-fact reasoning that keeps `CONNECTED_TO` off `NETWORK_CLOSE`.
fn attach_session_relationship(event: &mut CanonicalEvent) {
    if event.event_type != EventType::ProcessExec {
        return;
    }
    let (Some(process), Some(session)) = (event.process.as_ref(), event.session.as_ref()) else {
        return;
    };
    let edge = EntityRelationship {
        from: EntityRef::Process {
            process_key: process.process_key,
        },
        to: EntityRef::Session {
            session_id: session.session_id.clone(),
        },
        relation: Relation::TriggeredBySession,
        event_id: event.event_id,
        timestamp: event.timestamp,
    };
    event.relationships.push(edge);
}

/// Writes the §9.4 `Process -EXECUTED_AS-> User` edge (plan Global
/// Constraint #8). Requires a real uid transition: a target uid that is
/// present *and different from* the acting uid. `PRIVILEGE_GID_CHANGE`
/// never produces one (`EntityRef::User` is keyed by uid; there is no
/// group entity, and encoding a gid there would corrupt the graph), and
/// `PRIVILEGE_SUDO` produces one only if the backend did report a target
/// uid — auditd's `USER_CMD` usually does not (plan Global Constraint #9),
/// and an edge citing an invented target is worse than no edge.
fn attach_executed_as_relationship(event: &mut CanonicalEvent) {
    if event.event_type == EventType::PrivilegeGidChange {
        return;
    }
    let Some(process) = event.process.as_ref() else {
        return;
    };
    let Some(target_uid) = event
        .event_data
        .get("target_uid")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
    else {
        return;
    };
    if event.user.as_ref().map(|u| u.uid) == Some(target_uid) {
        return;
    }
    let edge = EntityRelationship {
        from: EntityRef::Process {
            process_key: process.process_key,
        },
        to: EntityRef::User {
            host_id: event.host_id,
            uid: target_uid,
        },
        relation: Relation::ExecutedAs,
        event_id: event.event_id,
        timestamp: event.timestamp,
    };
    event.relationships.push(edge);
}
```

Leave `enrich_process_event`, `enrich_non_process_event`, `attach_file_relationship`, `attach_network_relationship`, `attach_dns_relationships` and `current_ppid` exactly as they are.

- [ ] **Step 12: Wire the resolver into `Pipeline` and re-export it**

In `crates/osiris-pipeline/src/pipeline.rs`, add the import and the field:

```rust
use crate::session_resolver::SessionResolver;
```

```rust
pub struct Pipeline {
    host: HostRef,
    boot_id: String,
    resolver: ProcessResolver,
    sessions: SessionResolver,
    priority_table: PriorityTable,
}

impl Pipeline {
    pub fn new(host: HostRef, boot_id: String) -> Self {
        Self {
            host,
            boot_id,
            resolver: ProcessResolver::new(),
            sessions: SessionResolver::new(),
            priority_table: PriorityTable::default(),
        }
    }

    /// Runs Normalize -> Enrich(local) -> Validate -> Prioritize on one raw
    /// event (ARCHITECTURE.md §7.1). Validation failures are tagged, never
    /// dropped — the caller always gets a PrioritizedEvent back.
    pub fn process(&mut self, raw: RawEvent) -> PrioritizedEvent {
        let event = normalize(raw, &self.host, &self.boot_id);
        let mut event = enrich(event, &self.boot_id, &mut self.resolver, &mut self.sessions);
        validate(&mut event);
        let lane = prioritize(&event, &self.priority_table);
        PrioritizedEvent { event, lane }
    }
}
```

In `crates/osiris-pipeline/src/lib.rs`, replace the module list and re-exports with:

```rust
pub mod enrich;
pub mod normalize;
pub mod pipeline;
pub mod prioritize;
pub mod process_resolver;
pub mod session_resolver;
pub mod validate;

pub use enrich::enrich;
pub use normalize::normalize;
pub use pipeline::{Pipeline, PrioritizedEvent};
pub use prioritize::{prioritize, PriorityLane, PriorityTable};
pub use process_resolver::ProcessResolver;
pub use session_resolver::{SessionRecord, SessionResolver};
pub use validate::validate;
```

- [ ] **Step 13: Run the enrich tests to verify they pass**

Run: `cargo test -p osiris-pipeline enrich`
Expected: PASS — every pre-existing enrich test (with its mechanical 4th-argument update) plus the eight new ones.

- [ ] **Step 14: Write the failing validate and prioritize tests**

Append to `crates/osiris-pipeline/src/validate.rs`'s `#[cfg(test)] mod tests`:

```rust
    fn identity_event() -> CanonicalEvent {
        let mut event = valid_event();
        event.event_type = EventType::SessionLogin;
        event.category = Category::Identity;
        event.session = Some(osiris_schema::SessionRef {
            session_id: "3".to_string(),
            tty: None,
            remote_addr: None,
            auth_method: None,
        });
        event
    }

    #[test]
    fn an_identity_event_with_a_session_id_is_valid() {
        let mut event = identity_event();
        assert!(validate(&mut event));
        assert!(!event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn an_identity_event_without_a_session_is_invalid_but_still_forwarded() {
        let mut event = identity_event();
        event.session = None;
        assert!(!validate(&mut event));
        assert!(event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn an_identity_event_with_a_blank_session_id_is_invalid() {
        let mut event = identity_event();
        event.session = Some(osiris_schema::SessionRef {
            session_id: "   ".to_string(),
            tty: None,
            remote_addr: None,
            auth_method: None,
        });
        assert!(!validate(&mut event));
    }

    fn privilege_event() -> CanonicalEvent {
        let mut event = valid_event();
        event.event_type = EventType::PrivilegeUidChange;
        event.category = Category::Privilege;
        event.user = Some(osiris_schema::UserRef {
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
            username: None,
            loginuid: Some(1000),
        });
        event
    }

    #[test]
    fn a_privilege_event_with_an_actor_and_a_user_is_valid() {
        let mut event = privilege_event();
        assert!(validate(&mut event));
    }

    #[test]
    fn a_privilege_event_without_a_user_is_invalid() {
        let mut event = privilege_event();
        event.user = None;
        assert!(!validate(&mut event));
        assert!(event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn a_privilege_event_without_a_process_is_invalid() {
        let mut event = privilege_event();
        event.process = None;
        assert!(!validate(&mut event));
    }
```

Note: `valid_event()` in that module currently builds a `ProcessExec` event with a populated `process`; confirm it does before relying on it (read the helper), and if it does not populate `process`, add `event.process = Some(...)` inside `privilege_event()` using the same `ProcessRef` shape the module's other helpers use.

Append to `crates/osiris-pipeline/src/prioritize.rs`'s `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn identity_events_take_the_normal_lane() {
        let table = PriorityTable::default();
        for event_type in [
            EventType::SessionLogin,
            EventType::SessionLogout,
            EventType::SessionCreate,
            EventType::SessionTerminate,
        ] {
            let mut event = exec_event();
            event.event_type = event_type;
            assert_eq!(table.lane_for(&event), PriorityLane::Normal);
        }
    }

    /// ARCHITECTURE.md §26 step 3's own example of a HIGH-lane assignment
    /// is "an event that matters more than the ambient stream". A uid
    /// transition and a sudo invocation are exactly that; a gid transition
    /// is not — daemons setgid at startup as a matter of routine.
    #[test]
    fn uid_changes_and_sudo_take_the_high_lane_but_gid_changes_do_not() {
        let table = PriorityTable::default();

        let mut uid_change = exec_event();
        uid_change.event_type = EventType::PrivilegeUidChange;
        assert_eq!(table.lane_for(&uid_change), PriorityLane::High);

        let mut sudo = exec_event();
        sudo.event_type = EventType::PrivilegeSudo;
        assert_eq!(table.lane_for(&sudo), PriorityLane::High);

        let mut gid_change = exec_event();
        gid_change.event_type = EventType::PrivilegeGidChange;
        assert_eq!(table.lane_for(&gid_change), PriorityLane::Normal);
    }
```

- [ ] **Step 15: Run them to verify they fail, then implement**

Run: `cargo test -p osiris-pipeline validate prioritize`
Expected: FAIL — identity/privilege events pass validation unconditionally (no required-field check yet) and land in the default `Normal` lane (so the High-lane assertions fail).

In `crates/osiris-pipeline/src/validate.rs`, insert these two blocks immediately before the closing `if !valid { ... }`:

```rust
    if matches!(
        event.event_type,
        osiris_schema::EventType::SessionLogin
            | osiris_schema::EventType::SessionLogout
            | osiris_schema::EventType::SessionCreate
            | osiris_schema::EventType::SessionTerminate
    ) {
        // A session event with no session id names nothing — nothing can
        // be correlated to it, and the Identity Story cannot find it.
        let has_session = event
            .session
            .as_ref()
            .map(|s| !s.session_id.trim().is_empty())
            .unwrap_or(false);
        if !has_session {
            valid = false;
        }
    }
    if matches!(
        event.event_type,
        osiris_schema::EventType::PrivilegeUidChange
            | osiris_schema::EventType::PrivilegeGidChange
            | osiris_schema::EventType::PrivilegeSudo
    ) {
        // A privilege transition with no actor and no acting user cannot be
        // attributed, explained in an alert, or joined to anything.
        if event.process.is_none() || event.user.is_none() {
            valid = false;
        }
    }
```

In `crates/osiris-pipeline/src/prioritize.rs`, append these entries to the `table: vec![...]` literal inside `impl Default for PriorityTable`, after the existing `(EventType::DnsQuery, PriorityLane::Normal),` line:

```rust
                (EventType::SessionLogin, PriorityLane::Normal),
                (EventType::SessionLogout, PriorityLane::Normal),
                (EventType::SessionCreate, PriorityLane::Normal),
                (EventType::SessionTerminate, PriorityLane::Normal),
                // A uid transition and a sudo invocation are the two
                // events in this phase that most directly answer "did
                // someone gain privilege" — §8.1's HIGH lane exists for
                // exactly this, and both are far rarer than the ambient
                // exec/file/network stream, so promoting them costs the
                // lower lanes nothing.
                (EventType::PrivilegeUidChange, PriorityLane::High),
                (EventType::PrivilegeSudo, PriorityLane::High),
                // A gid transition stays Normal: daemons setgid at startup
                // as a matter of routine, so it is not the rare, decisive
                // signal the two above are.
                (EventType::PrivilegeGidChange, PriorityLane::Normal),
```

- [ ] **Step 16: Write the failing full-pipeline integration test**

Append to `crates/osiris-pipeline/src/pipeline.rs`'s `#[cfg(test)] mod tests`:

```rust
    /// The whole Normalize -> Enrich -> Validate -> Prioritize path for
    /// ARCHITECTURE.md §26's opening: a login, a shell inside it, and a
    /// privilege escalation inside that shell — the shape this phase
    /// exists to make work.
    #[tokio::test]
    async fn a_login_then_shell_then_escalation_is_fully_session_attributed() {
        use osiris_sensor_api::{
            IdentityEventRaw, IdentityOperation, PrivilegeEventRaw, PrivilegeOperation,
        };
        let host = test_host();
        let mut pipeline = Pipeline::new(host.clone(), "boot-1".to_string());

        let sshd = pipeline.process(RawEvent::ProcessExec(ProcessExecRaw {
            pid: 100,
            ppid: 1,
            uid: 0,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: 1_000,
            start_time_mono: 1_000,
            source: RawEventSource::Synthetic,
        }));
        assert!(sshd.event.session.is_none(), "no login observed yet");

        let login = pipeline.process(RawEvent::Identity(IdentityEventRaw {
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
        assert_eq!(login.lane, PriorityLane::Normal);
        assert!(!login.event.tags.contains(&"INVALID".to_string()));

        let bash = pipeline.process(RawEvent::ProcessExec(ProcessExecRaw {
            pid: 200,
            ppid: 100,
            uid: 1000,
            exe_path: "/bin/bash".to_string(),
            comm: "bash".to_string(),
            timestamp_ns: 3_000,
            start_time_mono: 3_000,
            source: RawEventSource::Synthetic,
        }));
        assert_eq!(bash.event.session.as_ref().unwrap().session_id, "3");
        assert!(bash
            .event
            .relationships
            .iter()
            .any(|r| r.relation == osiris_schema::Relation::TriggeredBySession));

        let escalation = pipeline.process(RawEvent::Privilege(PrivilegeEventRaw {
            operation: PrivilegeOperation::UidChange,
            pid: 200,
            ppid: 100,
            uid: 1000,
            gid: Some(1000),
            euid: Some(1000),
            egid: Some(1000),
            auid: Some(1000),
            session_id: Some("3".to_string()),
            username: None,
            target_uid: Some(0),
            target_gid: None,
            command: None,
            success: true,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: 4_000,
            audit_serial: Some(470),
            source: RawEventSource::Synthetic,
        }));
        assert_eq!(escalation.lane, PriorityLane::High);
        assert!(!escalation.event.tags.contains(&"INVALID".to_string()));
        assert_eq!(
            escalation
                .event
                .session
                .as_ref()
                .unwrap()
                .remote_addr
                .as_deref(),
            Some("198.51.100.10"),
            "the escalation must carry the SSH session's remote address, which is \
             what makes Task 6's rule expressible"
        );
        assert!(escalation
            .event
            .relationships
            .iter()
            .any(|r| r.relation == osiris_schema::Relation::ExecutedAs));
    }
```

`osiris-pipeline`'s `Cargo.toml` has no `tokio` dev-dependency and this test needs none — change `#[tokio::test]` to a plain `#[test]` and drop `async` from the signature. (The surrounding module's existing tests are plain `#[test]`; keep it consistent.)

- [ ] **Step 17: Run the whole crate's tests**

Run: `cargo test -p osiris-pipeline`
Expected: PASS — every test in normalize, enrich, validate, prioritize, session_resolver, process_resolver and pipeline.

- [ ] **Step 18: Commit**

```bash
git add crates/osiris-pipeline
git commit -m "feat(pipeline): identity/privilege normalization, SessionResolver, and the SSH/sudo edges

Normalize maps the four session and three privilege raw operations onto
their frozen EventTypes and populates UserRef/SessionRef (tagging
USER_REF_PARTIAL where auditd cannot report gid/euid/egid). A new
SessionResolver learns pid->session from SESSION_LOGIN and propagates it
down the process tree by ppid inheritance (ARCHITECTURE.md §26 step 3), so
every descendant event carries the session. Enrich writes the two
previously-unused §9.4 edges: Process -TRIGGERED_BY_SESSION-> Session on
PROCESS_EXEC, and Process -EXECUTED_AS-> User on a real uid transition.
Privilege uid-changes and sudo take the HIGH bus lane.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01CQ6yt1YUcRLAqQad8DthQc"
```

---

### Task 3: `osiris-sensors-identity` — the real Identity Sensor (audit-log backend)

**Files:**
- Create: `crates/osiris-sensors/identity/Cargo.toml`
- Create: `crates/osiris-sensors/identity/src/lib.rs`
- Create: `crates/osiris-sensors/identity/src/audit_record.rs`
- Create: `crates/osiris-sensors/identity/src/sensor.rs`
- Create: `crates/osiris-sensors/identity/tests/fixtures/ssh_sudo_session.log`
- Create: `crates/osiris-sensors/identity/tests/fixture_log.rs`
- Modify: `Cargo.toml` (workspace root — add `"crates/osiris-sensors/identity"` to `members`)
- Modify: `tools/check-dep-graph.sh`

**Interfaces:**
- Consumes (from Task 1 and Phase 1/2's crates): `osiris_sensor_api::{IdentityEventRaw, IdentityOperation, PrivilegeEventRaw, PrivilegeOperation, RawEvent, RawEventSource, Sensor, SensorCapabilities, SensorContext, SensorError, SensorHealth, SensorMetrics, SensorState}` and `osiris_fileutil::{LineTailer, parse_audit_msg_id, tokenize, AuditMsgId}`.
- Produces:
  - `osiris_sensors_identity::audit_record::RecordParts` — `pub struct RecordParts { pub id: AuditMsgId, pub record_type: String, pub outer: HashMap<String, String>, pub inner: HashMap<String, String> }`, plus `impl RecordParts { pub fn get(&self, key: &str) -> Option<&str> }`.
  - `osiris_sensors_identity::audit_record::split_record(line: &str) -> Option<RecordParts>` — the header / outer-body / inner-`msg` split Global Constraint #9 requires.
  - `osiris_sensors_identity::audit_record::IdentityRecord` — `pub enum IdentityRecord { Identity(IdentityEventRaw), Privilege(PrivilegeEventRaw) }`.
  - `osiris_sensors_identity::audit_record::parse_record(line: &str) -> Option<IdentityRecord>`.
  - `osiris_sensors_identity::IdentitySensor` implementing `Sensor`, with `IdentitySensor::new(audit_log_path: impl Into<PathBuf>) -> Self` and `with_poll_interval(self, Duration) -> Self`. Task 5's Agent wiring constructs this.
- `osiris-fileutil` is **not** modified (Global Constraint #9): `tokenize`'s `HashMap` contract is correct for what it promises, and the nested-`msg` split is Identity-record-specific knowledge, kept in the sensor crate exactly as `osiris-sensors-fs` keeps its `PATH`-record hex-decoding.

**Before writing any code**, open `crates/osiris-fileutil/src/audit_kv.rs` and confirm three things this task depends on: `tokenize` returns `HashMap<String, String>` (so a second `msg=` on one line genuinely overwrites the first); `parse_audit_msg_id` accepts a value with a trailing `:` (its doc comment says so, and `inner.split(')').next()` implements it); and `tokenize` strips surrounding double quotes but does **not** hex-decode unquoted values. Also open `crates/osiris-sensors/fs/src/audit_record.rs` and read `decode_untrusted_string`/`decode_hex` — this task reimplements those two helpers for `USER_CMD`'s `cmd=` field rather than importing them, because `osiris-sensors-fs` is a sibling sensor crate and one sensor must never depend on another (§4.2).

- [ ] **Step 1: Create the crate manifest**

`crates/osiris-sensors/identity/Cargo.toml`:
```toml
[package]
name = "osiris-sensors-identity"
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

Note the absence of `osiris-schema`: unlike `osiris-sensors-fs` (which needs `encode_device_id`), this sensor produces only `osiris-sensor-api` raw types and needs no schema symbol. Do not add the dependency "for symmetry".

- [ ] **Step 2: Add the crate to the workspace and register the boundary check**

In the workspace root `Cargo.toml`, update `members`:
```toml
members = ["crates/*", "crates/osiris-sensors/process", "crates/osiris-sensors/fs", "crates/osiris-sensors/net", "crates/osiris-sensors/identity", "generator"]
```
Leave `exclude = ["crates/osiris-sensors"]` untouched.

In `tools/check-dep-graph.sh`, add one line immediately after `check_forbidden osiris-sensors-net osiris-server osiris-api` (Global Constraint #15):
```bash
check_forbidden osiris-sensors-identity osiris-server osiris-api
```

- [ ] **Step 3: Write the failing tests for the record splitter and parser**

Create `crates/osiris-sensors/identity/src/audit_record.rs` containing only this test module for now (the implementation lands in Step 5). These are the real auditd record shapes this sensor parses; every one is a standard record type with standard field names per Global Constraint #9, and nothing outside that constraint's "confident" list is relied upon.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::{IdentityOperation, PrivilegeOperation, RawEventSource};

    // --- The seven record shapes this phase emits, in real auditd text ---

    /// `USER_LOGIN` reports the logging-in account as `id=<uid>` rather
    /// than `acct="name"` on most builds — hence `username: None` for this
    /// line, with `acct=` exercised on USER_START below.
    const USER_LOGIN: &str = r#"type=USER_LOGIN msg=audit(1690000000.123:456): pid=1200 uid=0 auid=1000 ses=3 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'"#;
    const USER_START: &str = r#"type=USER_START msg=audit(1690000000.130:457): pid=1200 uid=0 auid=1000 ses=3 msg='op=PAM:session_open grantors=pam_selinux,pam_loginuid,pam_keyinit acct="alice" exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'"#;
    const USER_END: &str = r#"type=USER_END msg=audit(1690000090.000:512): pid=1200 uid=0 auid=1000 ses=3 msg='op=PAM:session_close grantors=pam_selinux,pam_loginuid,pam_keyinit acct="alice" exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'"#;
    const USER_LOGOUT: &str = r#"type=USER_LOGOUT msg=audit(1690000090.010:513): pid=1200 uid=0 auid=1000 ses=3 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'"#;
    /// `cmd=` is hex-encoded whenever the command contains a byte outside
    /// printable-ASCII-minus-quote — which any command line with a space
    /// always does. `2F7573722F62696E2F77686F616D69` is `/usr/bin/whoami`.
    const USER_CMD: &str = r#"type=USER_CMD msg=audit(1690000005.000:469): pid=1400 uid=1000 auid=1000 ses=3 msg='cwd="/home/alice" cmd=2F7573722F62696E2F77686F616D69 exe="/usr/bin/sudo" terminal=pts/0 res=success'"#;
    /// x86_64 syscall 105 is `setuid(2)`; `a0` is its single argument, in
    /// lowercase hex with no `0x` prefix — `a0=0` means "become uid 0".
    const SYSCALL_SETUID: &str = r#"type=SYSCALL msg=audit(1690000005.010:470): arch=c000003e syscall=105 success=yes exit=0 a0=0 a1=7ffd0e2b1c40 a2=0 a3=0 items=0 ppid=200 pid=300 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="sudo" exe="/usr/bin/sudo" subj=unconfined key="osiris_identity""#;
    /// x86_64 syscall 106 is `setgid(2)`.
    const SYSCALL_SETGID: &str = r#"type=SYSCALL msg=audit(1690000005.020:471): arch=c000003e syscall=106 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=0 ppid=200 pid=300 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="sudo" exe="/usr/bin/sudo" subj=unconfined key="osiris_identity""#;

    // --- The splitter: header / outer body / inner msg ---

    /// Global Constraint #9's load-bearing consequence, stated as a test: a
    /// `USER_*` line has TWO `msg=` fields, and `tokenize`'s `HashMap` keeps
    /// only the last one, so feeding such a line to `tokenize` whole
    /// destroys the audit header. `split_record` must not.
    #[test]
    fn a_whole_user_line_fed_to_tokenize_loses_the_header_but_split_record_does_not() {
        // Proof of the hazard, so this fails loudly if `tokenize`'s
        // contract ever changes underneath us.
        let naive = osiris_fileutil::tokenize(USER_LOGIN);
        assert!(
            osiris_fileutil::parse_audit_msg_id(naive.get("msg").unwrap()).is_none(),
            "the nested msg='...' must be what a naive tokenize sees — if this ever \
             passes, re-read Global Constraint #9 before simplifying the splitter"
        );

        let parts = split_record(USER_LOGIN).expect("must split");
        assert_eq!(parts.id.timestamp_ns, 1_690_000_000_123_000_000);
        assert_eq!(parts.id.serial, 456);
        assert_eq!(parts.record_type, "USER_LOGIN");
    }

    #[test]
    fn split_record_separates_outer_fields_from_the_nested_msg_fields() {
        let parts = split_record(USER_START).expect("must split");
        // Outer body.
        assert_eq!(parts.outer.get("pid").map(String::as_str), Some("1200"));
        assert_eq!(parts.outer.get("uid").map(String::as_str), Some("0"));
        assert_eq!(parts.outer.get("auid").map(String::as_str), Some("1000"));
        assert_eq!(parts.outer.get("ses").map(String::as_str), Some("3"));
        // Inner sub-record.
        assert_eq!(parts.inner.get("acct").map(String::as_str), Some("alice"));
        assert_eq!(
            parts.inner.get("exe").map(String::as_str),
            Some("/usr/sbin/sshd")
        );
        assert_eq!(parts.inner.get("res").map(String::as_str), Some("success"));
        assert_eq!(
            parts.inner.get("addr").map(String::as_str),
            Some("198.51.100.10")
        );
        // `get` reads either layer, outer first.
        assert_eq!(parts.get("ses"), Some("3"));
        assert_eq!(parts.get("acct"), Some("alice"));
        assert_eq!(parts.get("nope"), None);
    }

    /// A `SYSCALL` record has no nested `msg='...'` at all — the splitter
    /// must treat that as the ordinary case, with an empty inner map,
    /// rather than rejecting the line.
    #[test]
    fn split_record_handles_a_record_with_no_nested_msg() {
        let parts = split_record(SYSCALL_SETUID).expect("must split");
        assert_eq!(parts.record_type, "SYSCALL");
        assert!(parts.inner.is_empty());
        assert_eq!(parts.outer.get("syscall").map(String::as_str), Some("105"));
        assert_eq!(parts.outer.get("a0").map(String::as_str), Some("0"));
        assert_eq!(parts.id.serial, 470);
    }

    #[test]
    fn split_record_rejects_a_line_with_no_audit_header() {
        assert!(split_record("this is not an audit record").is_none());
        assert!(split_record("type=USER_LOGIN pid=1200").is_none());
    }

    // --- Identity records ---

    #[test]
    fn parses_a_user_login_into_an_identity_login_event() {
        match parse_record(USER_LOGIN).expect("must parse") {
            IdentityRecord::Identity(i) => {
                assert_eq!(i.operation, IdentityOperation::Login);
                assert_eq!(i.session_id, "3");
                assert_eq!(i.pid, 1200);
                assert_eq!(i.uid, 0);
                assert_eq!(i.auid, Some(1000));
                // This record reported `id=1000`, not `acct=` — the name is
                // genuinely unknown, so it stays None rather than being
                // back-derived from the uid (Global Constraint #9).
                assert_eq!(i.username, None);
                assert_eq!(i.terminal.as_deref(), Some("/dev/pts/0"));
                assert_eq!(i.remote_addr.as_deref(), Some("198.51.100.10"));
                assert_eq!(i.auth_method.as_deref(), Some("sshd"));
                assert!(i.success);
                assert_eq!(i.exe_path, "/usr/sbin/sshd");
                assert_eq!(i.comm, "sshd");
                assert_eq!(i.timestamp_ns, 1_690_000_000_123_000_000);
                assert_eq!(i.audit_serial, Some(456));
                assert_eq!(i.source, RawEventSource::Audit);
            }
            other => panic!("expected an Identity record, got {other:?}"),
        }
    }

    #[test]
    fn parses_the_other_three_user_record_types_onto_their_operations() {
        for (line, expected) in [
            (USER_START, IdentityOperation::SessionStart),
            (USER_END, IdentityOperation::SessionEnd),
            (USER_LOGOUT, IdentityOperation::Logout),
        ] {
            match parse_record(line).expect("must parse") {
                IdentityRecord::Identity(i) => assert_eq!(i.operation, expected),
                other => panic!("expected an Identity record, got {other:?}"),
            }
        }
    }

    /// `acct="alice"` is the field that does carry a name, and it lives in
    /// the *nested* sub-record, not the outer body.
    #[test]
    fn reads_the_account_name_from_the_nested_sub_record() {
        match parse_record(USER_START).expect("must parse") {
            IdentityRecord::Identity(i) => assert_eq!(i.username.as_deref(), Some("alice")),
            other => panic!("expected an Identity record, got {other:?}"),
        }
    }

    /// Global Constraint #9's disclosed `?` handling: a local console login
    /// has no remote address, and auditd prints a literal `?`. That must
    /// become `None`, never `Some("?")`.
    #[test]
    fn an_unknown_address_or_terminal_becomes_none_not_a_question_mark() {
        let local = USER_LOGIN
            .replace("hostname=198.51.100.10", "hostname=?")
            .replace("addr=198.51.100.10", "addr=?")
            .replace("terminal=/dev/pts/0", "terminal=?");
        match parse_record(&local).expect("must parse") {
            IdentityRecord::Identity(i) => {
                assert_eq!(i.remote_addr, None);
                assert_eq!(i.terminal, None);
            }
            other => panic!("expected an Identity record, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_login_is_still_emitted_with_success_false() {
        let failed = USER_LOGIN.replace("res=success", "res=failed");
        match parse_record(&failed).expect("must parse") {
            IdentityRecord::Identity(i) => {
                assert_eq!(i.operation, IdentityOperation::Login);
                assert!(!i.success);
            }
            other => panic!("expected an Identity record, got {other:?}"),
        }
    }

    /// `ses=4294967295` is auditd's `(unsigned)-1` sentinel for "no audit
    /// session" (a daemon-initiated PAM open, say). A session-lifecycle
    /// record naming no session cannot be correlated to anything, and Task
    /// 2's `validate` would tag it INVALID; it is dropped here instead, and
    /// that drop is documented at `parse_record`.
    #[test]
    fn a_user_record_with_the_unset_session_sentinel_is_dropped() {
        assert!(parse_record(&USER_LOGIN.replace("ses=3", "ses=4294967295")).is_none());
        assert!(parse_record(&USER_LOGIN.replace(" ses=3", "")).is_none());
    }

    #[test]
    fn an_unset_auid_sentinel_becomes_none_rather_than_four_billion() {
        let line = USER_LOGIN.replace("auid=1000", "auid=4294967295");
        match parse_record(&line).expect("must parse") {
            IdentityRecord::Identity(i) => assert_eq!(i.auid, None),
            other => panic!("expected an Identity record, got {other:?}"),
        }
    }

    // --- Privilege records ---

    #[test]
    fn parses_a_setuid_syscall_into_a_uid_change_with_its_target() {
        match parse_record(SYSCALL_SETUID).expect("must parse") {
            IdentityRecord::Privilege(p) => {
                assert_eq!(p.operation, PrivilegeOperation::UidChange);
                assert_eq!(p.pid, 300);
                assert_eq!(p.ppid, 200);
                assert_eq!(p.uid, 1000);
                // A SYSCALL record reports these for real, so they are Some
                // and Task 2 will NOT tag the event USER_REF_PARTIAL.
                assert_eq!(p.gid, Some(1000));
                assert_eq!(p.euid, Some(0));
                assert_eq!(p.egid, Some(1000));
                assert_eq!(p.auid, Some(1000));
                assert_eq!(p.session_id.as_deref(), Some("3"));
                assert_eq!(p.username, None);
                assert_eq!(p.target_uid, Some(0));
                assert_eq!(p.target_gid, None);
                assert_eq!(p.command, None);
                assert!(p.success);
                assert_eq!(p.exe_path, "/usr/bin/sudo");
                assert_eq!(p.comm, "sudo");
                assert_eq!(p.timestamp_ns, 1_690_000_005_010_000_000);
                assert_eq!(p.audit_serial, Some(470));
            }
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_setgid_syscall_into_a_gid_change_with_target_gid_not_target_uid() {
        match parse_record(SYSCALL_SETGID).expect("must parse") {
            IdentityRecord::Privilege(p) => {
                assert_eq!(p.operation, PrivilegeOperation::GidChange);
                assert_eq!(p.target_gid, Some(0));
                assert_eq!(
                    p.target_uid, None,
                    "a setgid record must never populate target_uid — Task 2's \
                     EXECUTED_AS edge is keyed on it and EntityRef::User has no gid"
                );
            }
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    /// `a0=ffffffff` is `(uid_t)-1`: "leave this id unchanged". It is not a
    /// transition to uid 4,294,967,295 and must not be reported as one.
    #[test]
    fn a_minus_one_argument_becomes_none_rather_than_a_four_billion_target() {
        let line = SYSCALL_SETUID.replace("a0=0 ", "a0=ffffffff ");
        match parse_record(&line).expect("must parse") {
            IdentityRecord::Privilege(p) => assert_eq!(p.target_uid, None),
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_setuid_is_still_emitted_with_success_false() {
        let line = SYSCALL_SETUID.replace("success=yes", "success=no");
        match parse_record(&line).expect("must parse") {
            IdentityRecord::Privilege(p) => assert!(!p.success),
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    /// Only 105 and 106 are privilege transitions this phase parses. 59
    /// (execve) belongs to the Process/Exec sensor, and 113/114
    /// (setresuid/setresgid) are deliberately out of scope (Global
    /// Constraint #3) — all must be ignored, never guessed at.
    #[test]
    fn other_syscall_numbers_are_ignored_including_the_deliberately_deferred_ones() {
        for nr in ["59", "113", "114", "257", "90"] {
            let line = SYSCALL_SETUID.replace("syscall=105", &format!("syscall={nr}"));
            assert!(
                parse_record(&line).is_none(),
                "syscall={nr} must not produce a privilege event this phase"
            );
        }
    }

    #[test]
    fn parses_a_user_cmd_into_a_sudo_event_with_a_hex_decoded_command() {
        match parse_record(USER_CMD).expect("must parse") {
            IdentityRecord::Privilege(p) => {
                assert_eq!(p.operation, PrivilegeOperation::Sudo);
                assert_eq!(p.pid, 1400);
                // USER_CMD carries no ppid= — 0 is the "no parent reported"
                // convention Task 1 documented, not an invented pid.
                assert_eq!(p.ppid, 0);
                assert_eq!(p.uid, 1000);
                // ...and no gid/euid/egid, so Task 2 tags the resulting
                // event USER_REF_PARTIAL (Global Constraint #6).
                assert_eq!((p.gid, p.euid, p.egid), (None, None, None));
                assert_eq!(p.session_id.as_deref(), Some("3"));
                assert_eq!(p.command.as_deref(), Some("/usr/bin/whoami"));
                // Global Constraint #9: the target account is NOT reliably
                // reported on USER_CMD, so none is ever claimed.
                assert_eq!(p.target_uid, None);
                assert_eq!(p.target_gid, None);
                assert_eq!(p.exe_path, "/usr/bin/sudo");
                assert_eq!(p.comm, "sudo");
                assert!(p.success);
            }
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    /// A quoted `cmd="..."` (a short, space-free command) must be taken
    /// literally, not hex-decoded — the same quoted/unquoted distinction
    /// `osiris-sensors-fs` draws for `name=`/`cwd=`.
    #[test]
    fn a_quoted_command_is_not_hex_decoded() {
        let line = USER_CMD.replace(
            "cmd=2F7573722F62696E2F77686F616D69",
            r#"cmd="deadbeef""#,
        );
        match parse_record(&line).expect("must parse") {
            IdentityRecord::Privilege(p) => assert_eq!(p.command.as_deref(), Some("deadbeef")),
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    /// Some sudo/audit builds omit `exe=` from USER_CMD entirely. The
    /// result is an empty exe_path/comm — the same "unknown, not invented"
    /// convention the Network sensor uses for an unattributed socket — not
    /// a hard-coded `/usr/bin/sudo`.
    #[test]
    fn a_user_cmd_without_an_exe_field_reports_an_empty_path_rather_than_guessing() {
        let line = USER_CMD.replace(r#" exe="/usr/bin/sudo""#, "");
        match parse_record(&line).expect("must parse") {
            IdentityRecord::Privilege(p) => {
                assert_eq!(p.exe_path, "");
                assert_eq!(p.comm, "");
            }
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    /// A `USER_CMD` with no `ses=` is still a real privilege event: unlike a
    /// session-lifecycle record it names something (a command run under
    /// sudo), so it is emitted with `session_id: None` rather than dropped.
    #[test]
    fn a_user_cmd_without_a_session_is_emitted_with_no_session_rather_than_dropped() {
        let line = USER_CMD.replace(" ses=3", "");
        match parse_record(&line).expect("must parse") {
            IdentityRecord::Privilege(p) => assert_eq!(p.session_id, None),
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    // --- Everything else in the log is not ours ---

    #[test]
    fn unrelated_record_types_are_ignored() {
        for line in [
            r#"type=PROCTITLE msg=audit(1690000000.123:456): proctitle=726D"#,
            r#"type=PATH msg=audit(1690000000.123:456): item=0 name="/tmp/foo" nametype=CREATE"#,
            r#"type=CRED_ACQ msg=audit(1690000000.140:458): pid=1200 uid=0 auid=1000 ses=3 msg='op=PAM:setcred acct="root" exe="/usr/sbin/sshd" res=success'"#,
            r#"type=CWD msg=audit(1690000000.123:456): cwd="/home/alice""#,
        ] {
            assert!(parse_record(line).is_none(), "must ignore: {line}");
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test -p osiris-sensors-identity`
Expected: FAIL to compile — `cannot find function split_record`, `cannot find enum IdentityRecord`, `cannot find function parse_record`.

- [ ] **Step 5: Implement the record splitter and parser**

Prepend to `crates/osiris-sensors/identity/src/audit_record.rs` (above the test module written in Step 3):

```rust
use std::collections::HashMap;

use osiris_fileutil::{parse_audit_msg_id, tokenize, AuditMsgId};
use osiris_sensor_api::{
    IdentityEventRaw, IdentityOperation, PrivilegeEventRaw, PrivilegeOperation, RawEventSource,
};

/// auditd's `(unsigned)-1` sentinel, printed for an unset `auid=`/`ses=`
/// and for a `setuid`/`setgid` argument meaning "leave this id unchanged".
const UNSET_ID: &str = "4294967295";

/// One auditd record, split into the three layers a `USER_*` line actually
/// has: the `type=… msg=audit(<secs>.<millis>:<serial>):` header, the outer
/// `key=value` body, and the single-quoted `msg='…'` sub-record.
///
/// This split is mandatory, not a convenience (Phase 4a plan Global
/// Constraint #9): `osiris_fileutil::tokenize` returns a `HashMap`, so
/// tokenizing a whole `USER_*` line lets the nested `msg='…'` overwrite the
/// header's `msg=audit(…)` value and destroys the timestamp and serial.
/// Nothing in this crate ever calls `tokenize` on a whole `USER_*` line.
#[derive(Debug, Clone)]
pub struct RecordParts {
    pub id: AuditMsgId,
    pub record_type: String,
    pub outer: HashMap<String, String>,
    pub inner: HashMap<String, String>,
}

impl RecordParts {
    /// Reads a field from either layer, outer first. The two layers never
    /// carry the same key in the record types this sensor parses, so the
    /// precedence is a tiebreak that is not exercised in practice — but it
    /// is defined here rather than left to iteration order.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.outer
            .get(key)
            .or_else(|| self.inner.get(key))
            .map(String::as_str)
    }
}

/// Splits one auditd line into header / outer body / inner `msg='…'`.
/// Returns `None` for any line with no parseable `msg=audit(…):` header —
/// never panics, never half-parses.
pub fn split_record(line: &str) -> Option<RecordParts> {
    // The header always ends `…:<serial>): `. Splitting there is exact: the
    // sequence `"): "` cannot occur earlier, because everything before it
    // is `type=<T> msg=audit(<digits>.<digits>:<digits>)`.
    let end = line.find("): ")?;
    // `..end + 2` keeps the trailing `:`, which `parse_audit_msg_id`
    // explicitly accepts (see its doc comment in osiris-fileutil).
    let header = &line[..end + 2];
    let body = &line[end + 3..];

    let header_fields = tokenize(header);
    let id = parse_audit_msg_id(header_fields.get("msg")?)?;
    let record_type = header_fields.get("type")?.clone();

    // Carve the nested sub-record out of the body before tokenizing what
    // remains, so neither layer's fields can shadow the other's.
    let (outer_text, inner_text) = match body.find("msg='") {
        Some(start) => {
            let after = &body[start + 5..];
            match after.find('\'') {
                Some(close) => {
                    let mut outer = String::with_capacity(body.len());
                    outer.push_str(&body[..start]);
                    outer.push_str(&after[close + 1..]);
                    (outer, after[..close].to_string())
                }
                // An unterminated quote: treat the remainder as the inner
                // sub-record rather than dropping the record outright. The
                // caller's required-field lookups then decide whether
                // enough survived to build an event.
                None => (body[..start].to_string(), after.to_string()),
            }
        }
        None => (body.to_string(), String::new()),
    };

    Some(RecordParts {
        id,
        record_type,
        outer: tokenize(&outer_text),
        inner: tokenize(&inner_text),
    })
}

/// The two disjoint record families this sensor emits (Phase 4a plan Global
/// Constraint #4). One `LineTailer` over one audit log produces both; there
/// is no separate privilege sensor in ARCHITECTURE.md §4.3's catalog to
/// produce the second.
#[derive(Debug, Clone)]
pub enum IdentityRecord {
    Identity(IdentityEventRaw),
    Privilege(PrivilegeEventRaw),
}

/// Parses one auditd line into whichever raw event it represents, or `None`
/// when the line is not one of this phase's seven record shapes.
///
/// Deliberate drops (all disclosed in the plan's Global Constraints #3/#9,
/// none of them silent guesses):
/// * every record type other than `USER_LOGIN`/`USER_LOGOUT`/`USER_START`/
///   `USER_END`/`USER_CMD`/`SYSCALL`;
/// * a `SYSCALL` record whose `syscall=` is not 105 (`setuid`) or 106
///   (`setgid`) — `setresuid`/`setresgid`/`capset` are out of scope;
/// * a `USER_*` session-lifecycle record with no usable `ses=` (absent, or
///   the `4294967295` unset sentinel). Such a record names no session, so
///   nothing could ever correlate to it and Task 2's `validate` would tag
///   the resulting event INVALID. A `USER_CMD` is *not* dropped for the
///   same reason: it names a command, and its session is `Option`al.
pub fn parse_record(line: &str) -> Option<IdentityRecord> {
    let parts = split_record(line)?;
    match parts.record_type.as_str() {
        "USER_LOGIN" => identity(&parts, IdentityOperation::Login),
        "USER_LOGOUT" => identity(&parts, IdentityOperation::Logout),
        "USER_START" => identity(&parts, IdentityOperation::SessionStart),
        "USER_END" => identity(&parts, IdentityOperation::SessionEnd),
        "USER_CMD" => sudo(&parts, line),
        "SYSCALL" => match parts.get("syscall")?.parse::<u32>().ok()? {
            105 => syscall_privilege(&parts, PrivilegeOperation::UidChange),
            106 => syscall_privilege(&parts, PrivilegeOperation::GidChange),
            _ => None,
        },
        _ => None,
    }
}

fn identity(parts: &RecordParts, operation: IdentityOperation) -> Option<IdentityRecord> {
    let session_id = usable_session(parts.get("ses"))?;
    let exe_path = parts.get("exe").unwrap_or_default().to_string();
    Some(IdentityRecord::Identity(IdentityEventRaw {
        operation,
        session_id,
        pid: parts.get("pid")?.parse().ok()?,
        uid: parts.get("uid")?.parse().ok()?,
        auid: parse_id(parts.get("auid")),
        // `acct="name"` when the record carries a name; `USER_LOGIN` usually
        // reports `id=<uid>` instead, and a uid is not a name — so this
        // stays None rather than being back-derived (§9's confidence
        // boundary: unknown is None, never invented).
        username: unknown_to_none(parts.get("acct")).map(str::to_string),
        terminal: unknown_to_none(parts.get("terminal")).map(str::to_string),
        remote_addr: unknown_to_none(parts.get("addr")).map(str::to_string),
        auth_method: basename(&exe_path),
        success: parts.get("res") == Some("success"),
        comm: basename(&exe_path).unwrap_or_default(),
        exe_path,
        timestamp_ns: parts.id.timestamp_ns,
        audit_serial: Some(parts.id.serial),
        source: RawEventSource::Audit,
    }))
}

fn syscall_privilege(
    parts: &RecordParts,
    operation: PrivilegeOperation,
) -> Option<IdentityRecord> {
    // setuid/setgid's single argument, lowercase hex with no `0x` prefix.
    // `ffffffff` is `(uid_t)-1` — "leave unchanged", not a transition to
    // 4,294,967,295.
    let target = parts
        .get("a0")
        .and_then(|a0| u32::from_str_radix(a0, 16).ok())
        .filter(|v| *v != u32::MAX);
    let (target_uid, target_gid) = match operation {
        PrivilegeOperation::UidChange => (target, None),
        PrivilegeOperation::GidChange => (None, target),
        // Unreachable: only the two SYSCALL arms call this.
        PrivilegeOperation::Sudo => (None, None),
    };
    Some(IdentityRecord::Privilege(PrivilegeEventRaw {
        operation,
        pid: parts.get("pid")?.parse().ok()?,
        ppid: parts.get("ppid").and_then(|v| v.parse().ok()).unwrap_or(0),
        uid: parts.get("uid")?.parse().ok()?,
        gid: parts.get("gid").and_then(|v| v.parse().ok()),
        euid: parts.get("euid").and_then(|v| v.parse().ok()),
        egid: parts.get("egid").and_then(|v| v.parse().ok()),
        auid: parse_id(parts.get("auid")),
        session_id: usable_session(parts.get("ses")),
        // audit does not resolve uids to names on SYSCALL records.
        username: None,
        target_uid,
        target_gid,
        command: None,
        success: parts.get("success") == Some("yes"),
        exe_path: parts.get("exe").unwrap_or_default().to_string(),
        comm: parts.get("comm").unwrap_or_default().to_string(),
        timestamp_ns: parts.id.timestamp_ns,
        audit_serial: Some(parts.id.serial),
        source: RawEventSource::Audit,
    }))
}

fn sudo(parts: &RecordParts, line: &str) -> Option<IdentityRecord> {
    let exe_path = parts.get("exe").unwrap_or_default().to_string();
    Some(IdentityRecord::Privilege(PrivilegeEventRaw {
        operation: PrivilegeOperation::Sudo,
        pid: parts.get("pid")?.parse().ok()?,
        // USER_CMD carries no `ppid=`. 0 is the codebase's "no parent
        // reported" convention (see `PrivilegeEventRaw.ppid`'s doc comment
        // and `enrich::current_ppid`), and `SessionResolver::attach` treats
        // it as "nothing to inherit from" — never as pid 0.
        ppid: 0,
        uid: parts.get("uid")?.parse().ok()?,
        // USER_CMD reports none of these; Task 2 tags the resulting event
        // USER_REF_PARTIAL rather than mirroring them silently.
        gid: None,
        euid: None,
        egid: None,
        auid: parse_id(parts.get("auid")),
        session_id: usable_session(parts.get("ses")),
        username: unknown_to_none(parts.get("acct")).map(str::to_string),
        // Global Constraint #9: `USER_CMD` does not reliably report the
        // target account across distributions, so no target is claimed and
        // Task 2 therefore mints no EXECUTED_AS edge for a sudo event.
        target_uid: None,
        target_gid: None,
        command: parts
            .get("cmd")
            .map(|cmd| decode_untrusted_string(line, "cmd", cmd)),
        success: parts.get("res") == Some("success"),
        comm: basename(&exe_path).unwrap_or_default(),
        exe_path,
        timestamp_ns: parts.id.timestamp_ns,
        audit_serial: Some(parts.id.serial),
        source: RawEventSource::Audit,
    }))
}

/// auditd prints a literal `?` for an unknown `addr=`/`hostname=`/
/// `terminal=` — a local console login has no remote address. That is
/// "unknown", so it becomes `None`; `Some("?")` must never reach a
/// `SessionRef` (Phase 4a plan Global Constraint #9).
fn unknown_to_none(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty() && *v != "?" && *v != "(none)")
}

/// Parses a uid-like field, mapping auditd's unset sentinel to `None`
/// rather than to 4,294,967,295.
fn parse_id(value: Option<&str>) -> Option<u32> {
    value.filter(|v| *v != UNSET_ID)?.parse().ok()
}

/// A session id that can actually be correlated: present, non-empty, and
/// not the unset sentinel.
fn usable_session(value: Option<&str>) -> Option<String> {
    value
        .filter(|v| !v.is_empty() && *v != UNSET_ID && *v != "?")
        .map(str::to_string)
}

/// The file stem of an executable path — `"/usr/sbin/sshd"` -> `"sshd"`.
/// This is what lands in `SessionRef.auth_method` (§9.2) and, for records
/// carrying no `comm=`, in `comm`. Returns `None` for an empty path rather
/// than an empty string, so "no exe reported" stays distinguishable.
fn basename(exe_path: &str) -> Option<String> {
    let stem = exe_path.rsplit('/').next().unwrap_or_default();
    if stem.is_empty() {
        None
    } else {
        Some(stem.to_string())
    }
}

/// The kernel logs a string via `audit_log_untrustedstring`: a value
/// containing any byte outside printable-ASCII-minus-quote (a space, most
/// obviously, which every real sudo command line has) is logged
/// **unquoted, as uppercase hex** instead of `key="value"`. `cmd=` is the
/// one field this sensor reads that carries such a value, so it is decoded
/// here — exactly as `osiris_sensors_fs::audit_record` decodes `name=` and
/// `cwd=`. That crate is a sibling sensor, so the helper is duplicated
/// rather than imported: one sensor never depends on another (§4.2).
///
/// `tokenize` already strips quotes, so the quoted/unquoted distinction
/// cannot be read back off its output — a legitimately quoted, all-hex
/// command (`cmd="deadbeef"`) must not be mistaken for an encoded one.
/// This checks the raw line for the literal `cmd="` marker instead.
fn decode_untrusted_string(line: &str, key: &str, raw_value: &str) -> String {
    if line.contains(&format!("{key}=\"")) {
        return raw_value.to_string();
    }
    decode_hex(raw_value).unwrap_or_else(|| raw_value.to_string())
}

fn decode_hex(raw: &str) -> Option<String> {
    if raw.len() < 2 || raw.len() % 2 != 0 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_bytes().chunks_exact(2) {
        let hex_pair = std::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(hex_pair, 16).ok()?);
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}
```

Create `crates/osiris-sensors/identity/src/lib.rs`:

```rust
pub mod audit_record;
pub mod sensor;

pub use audit_record::{parse_record, split_record, IdentityRecord, RecordParts};
pub use sensor::IdentitySensor;
```

- [ ] **Step 6: Run the parser tests to verify they pass**

Run: `cargo test -p osiris-sensors-identity audit_record`
Expected: PASS — all 20 parser tests.

- [ ] **Step 7: Write the failing tests for the `Sensor` implementation**

Create `crates/osiris-sensors/identity/src/sensor.rs` containing only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::{IdentityOperation, PrivilegeOperation, RawEvent};
    use std::io::Write;
    use tokio::sync::mpsc;

    const USER_LOGIN: &str = r#"type=USER_LOGIN msg=audit(1690000000.123:456): pid=1200 uid=0 auid=1000 ses=3 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'"#;
    const SYSCALL_SETUID: &str = r#"type=SYSCALL msg=audit(1690000005.010:470): arch=c000003e syscall=105 success=yes exit=0 a0=0 a1=7ffd0e2b1c40 a2=0 a3=0 items=0 ppid=200 pid=300 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="sudo" exe="/usr/bin/sudo" subj=unconfined key="osiris_identity""#;

    #[tokio::test]
    async fn reports_unsupported_when_the_audit_log_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut sensor = IdentitySensor::new(dir.path().join("missing.log"));
        let caps = sensor.capabilities();
        assert!(!caps.supported());
        assert!(!caps.ebpf, "no eBPF backend exists this phase");
        assert!(caps
            .unsupported_reason
            .as_deref()
            .unwrap_or_default()
            .contains("audit log not found"));

        let (tx, _rx) = mpsc::channel(16);
        let result = sensor
            .initialize(SensorContext::new(tx, CancellationToken::new()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn reports_the_audit_fallback_capability_when_the_log_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();
        let sensor = IdentitySensor::new(&path);
        let caps = sensor.capabilities();
        assert!(caps.supported());
        assert!(!caps.ebpf);
        assert!(caps.audit_fallback);
        assert!(!caps.always_available);
        assert_eq!(sensor.name(), "identity");
    }

    /// The whole point of Global Constraint #4: ONE tail over ONE log emits
    /// BOTH families.
    #[tokio::test]
    async fn emits_both_an_identity_and_a_privilege_event_from_one_tailed_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();

        let mut sensor =
            IdentitySensor::new(&path).with_poll_interval(Duration::from_millis(20));
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
        writeln!(file, "{USER_LOGIN}").unwrap();
        // A record from another subsystem, interleaved: it must be ignored
        // without disturbing the two that surround it.
        writeln!(
            file,
            r#"type=PROCTITLE msg=audit(1690000005.005:469): proctitle=73756F"#
        )
        .unwrap();
        writeln!(file, "{SYSCALL_SETUID}").unwrap();
        file.flush().unwrap();

        let first = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out waiting for the identity event")
            .expect("channel closed unexpectedly");
        match first {
            RawEvent::Identity(raw) => {
                assert_eq!(raw.operation, IdentityOperation::Login);
                assert_eq!(raw.session_id, "3");
                assert_eq!(raw.remote_addr.as_deref(), Some("198.51.100.10"));
            }
            other => panic!("expected RawEvent::Identity first, got {other:?}"),
        }

        let second = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timed out waiting for the privilege event")
            .expect("channel closed unexpectedly");
        match second {
            RawEvent::Privilege(raw) => {
                assert_eq!(raw.operation, PrivilegeOperation::UidChange);
                assert_eq!(raw.target_uid, Some(0));
                assert_eq!(raw.pid, 300);
            }
            other => panic!("expected RawEvent::Privilege second, got {other:?}"),
        }

        sensor.stop().await.unwrap();
        let health = sensor.health();
        assert_eq!(health.events_emitted_total, 2);
        assert_eq!(health.state, SensorState::Stopped);
        assert_eq!(health.capability_flags, vec!["audit_fallback".to_string()]);
        assert_eq!(health.last_event_at, Some(1_690_000_005_010_000_000));
    }

    /// This sensor must never emit any other `RawEvent` variant — the same
    /// single-responsibility assertion the Filesystem and Network sensors'
    /// tests make.
    #[tokio::test]
    async fn emits_nothing_for_a_log_containing_only_other_subsystems_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(
            &path,
            "type=CWD msg=audit(1690000000.123:456): cwd=\"/home/alice\"\n\
             type=PATH msg=audit(1690000000.123:456): item=0 name=\"/tmp/foo\" nametype=CREATE\n\
             not an audit record at all\n",
        )
        .unwrap();

        let mut sensor =
            IdentitySensor::new(&path).with_poll_interval(Duration::from_millis(20));
        let (tx, mut rx) = mpsc::channel(16);
        let cancellation = CancellationToken::new();
        sensor
            .initialize(SensorContext::new(tx, cancellation.clone()))
            .await
            .unwrap();
        sensor.start().await.unwrap();

        let received = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(
            received.is_err(),
            "the Identity sensor must emit nothing for records it does not own"
        );
        sensor.stop().await.unwrap();
        assert_eq!(sensor.health().events_emitted_total, 0);
    }
}
```

- [ ] **Step 8: Run the sensor tests to verify they fail**

Run: `cargo test -p osiris-sensors-identity sensor`
Expected: FAIL to compile — `cannot find struct IdentitySensor`.

- [ ] **Step 9: Implement the `Sensor`**

Prepend to `crates/osiris-sensors/identity/src/sensor.rs` (above the test module written in Step 7). This deliberately mirrors `osiris-sensors-fs`'s `FilesystemSensor` — same `HealthState`, same `lock_health` poisoned-mutex recovery, same `initialize`-spawns-the-task lifecycle — minus the assembler, because every record this sensor parses is self-contained (there is no multi-record group to reassemble):

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

use crate::audit_record::{parse_record, IdentityRecord};

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

/// Locks a health mutex, recovering rather than panicking if a prior holder
/// panicked while holding it — the discipline established by
/// `osiris-sensors-process`, `osiris-sensors-fs` and `osiris-generator`.
fn lock_health(health: &Mutex<HealthState>) -> MutexGuard<'_, HealthState> {
    health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The Identity/Session sensor (ARCHITECTURE.md §4.3's Identity/Session
/// row), Phase 4a scope: the Linux Audit backend only, consumed by tailing
/// an auditd-format log file. `utmp`/`wtmp` polling and
/// `/proc/<pid>/loginuid` are NOT implemented — see the plan's Global
/// Constraint #2 for why (a binary, architecture-dependent C-struct layout
/// this codebase would be guessing at; and a per-process lookup rather than
/// an event source). Those are additional `Sensor` implementations behind
/// this same unchanged trait, not a rewrite of this one.
///
/// Per plan Global Constraint #4, this one sensor emits BOTH
/// `RawEvent::Identity` (session lifecycle) and `RawEvent::Privilege`
/// (uid/gid transitions and sudo): §4.3's catalog has no separate Privilege
/// sensor row, and the audit stream carrying `USER_*` carries `USER_CMD`
/// and `SYSCALL` too. That is deliberate, not a leaked responsibility.
///
/// Unlike `FilesystemSensor` there is no `with_audit_key` filter: `USER_*`
/// records carry no `key=` field at all (only `SYSCALL` records do), so a
/// key filter would suppress exactly the identity records this sensor
/// exists for. The record-type match in `parse_record` is the filter.
///
/// Expected audit rules on a real host (the sensor does not install them;
/// that is an operator/packaging concern — the `USER_*` records need no
/// rule at all, since PAM and login emit them unconditionally):
/// ```text
/// -a always,exit -F arch=b64 -S setuid,setgid -F key=osiris_identity
/// ```
pub struct IdentitySensor {
    audit_log_path: PathBuf,
    poll_interval: Duration,
    cancellation: Option<CancellationToken>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    health: Arc<Mutex<HealthState>>,
}

impl IdentitySensor {
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
impl Sensor for IdentitySensor {
    fn name(&self) -> &'static str {
        "identity"
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
                            // Every record is self-contained — no assembler,
                            // no completion timeout, nothing to flush on
                            // shutdown (contrast FilesystemSensor, whose
                            // SYSCALL+PATH+CWD groups span several lines).
                            if let Some(record) = parse_record(&line) {
                                emit(&output, record, &health).await;
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
        // The polling task is already spawned in initialize(); this sensor
        // has no separate "armed but not running" state, same as
        // ProcessExecSensor and FilesystemSensor.
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
    record: IdentityRecord,
    health: &Mutex<HealthState>,
) {
    let raw = match record {
        IdentityRecord::Identity(i) => RawEvent::Identity(i),
        IdentityRecord::Privilege(p) => RawEvent::Privilege(p),
    };
    let timestamp = raw.timestamp_ns();
    if output.send(raw).await.is_ok() {
        let mut h = lock_health(health);
        h.events_emitted_total += 1;
        h.last_event_at = Some(timestamp);
        h.state = SensorState::Healthy;
    } else {
        lock_health(health).events_dropped_total += 1;
    }
}
```

- [ ] **Step 10: Run the sensor tests to verify they pass**

Run: `cargo test -p osiris-sensors-identity`
Expected: PASS — all parser tests plus the four sensor tests.

- [ ] **Step 11: Add the whole-log fixture and its integration test**

The unit tests above exercise one record shape at a time. This adds a single fixture file in real auditd layout containing an entire SSH-login-to-sudo-escalation session interleaved with other subsystems' records, so the crate is proven against a log that looks like a real one and not only against curated single lines.

Create `crates/osiris-sensors/identity/tests/fixtures/ssh_sudo_session.log` (exactly these 12 lines, no trailing blank line):
```text
type=USER_LOGIN msg=audit(1690000000.123:456): pid=1200 uid=0 auid=1000 ses=3 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'
type=USER_START msg=audit(1690000000.130:457): pid=1200 uid=0 auid=1000 ses=3 msg='op=PAM:session_open grantors=pam_selinux,pam_loginuid,pam_keyinit acct="alice" exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'
type=CRED_ACQ msg=audit(1690000000.140:458): pid=1200 uid=0 auid=1000 ses=3 msg='op=PAM:setcred grantors=pam_env,pam_unix acct="alice" exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'
type=SYSCALL msg=audit(1690000001.000:460): arch=c000003e syscall=59 success=yes exit=0 a0=55f1 a1=55f2 a2=55f3 a3=0 items=2 ppid=1200 pid=200 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="bash" exe="/bin/bash" subj=unconfined key=(null)
type=PROCTITLE msg=audit(1690000001.000:460): proctitle=2D62617368
type=USER_CMD msg=audit(1690000005.000:469): pid=1400 uid=1000 auid=1000 ses=3 msg='cwd="/home/alice" cmd=2F7573722F62696E2F77686F616D69 exe="/usr/bin/sudo" terminal=pts/0 res=success'
type=SYSCALL msg=audit(1690000005.010:470): arch=c000003e syscall=105 success=yes exit=0 a0=0 a1=7ffd0e2b1c40 a2=0 a3=0 items=0 ppid=200 pid=300 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="sudo" exe="/usr/bin/sudo" subj=unconfined key="osiris_identity"
type=SYSCALL msg=audit(1690000005.020:471): arch=c000003e syscall=106 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=0 ppid=200 pid=300 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="sudo" exe="/usr/bin/sudo" subj=unconfined key="osiris_identity"
type=SYSCALL msg=audit(1690000006.000:475): arch=c000003e syscall=113 success=yes exit=0 a0=0 a1=0 a2=ffffffff a3=0 items=0 ppid=200 pid=300 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="sudo" exe="/usr/bin/sudo" subj=unconfined key="osiris_identity"
type=USER_LOGIN msg=audit(1690000010.000:480): pid=1500 uid=0 auid=0 ses=4 msg='op=login id=0 exe="/bin/login" hostname=? addr=? terminal=tty1 res=success'
type=USER_END msg=audit(1690000090.000:512): pid=1200 uid=0 auid=1000 ses=3 msg='op=PAM:session_close grantors=pam_selinux,pam_loginuid,pam_keyinit acct="alice" exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'
type=USER_LOGOUT msg=audit(1690000090.010:513): pid=1200 uid=0 auid=1000 ses=3 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'
```

Besides the seven owned shapes, that log deliberately contains: a `CRED_ACQ` and a `PROCTITLE` (other subsystems); an `execve` SYSCALL (the Process/Exec sensor's record, not this one's); a `setresuid` SYSCALL (syscall 113 — the deliberately-deferred variant from Global Constraint #3); and a local console `USER_LOGIN` with `addr=?`/`hostname=?`.

Create `crates/osiris-sensors/identity/tests/fixture_log.rs`:

```rust
use osiris_sensors_identity::{parse_record, IdentityRecord};

fn fixture_lines() -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ssh_sudo_session.log");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()))
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// Exactly the owned records are picked out of a realistic mixed log:
/// 5 identity (2 logins, session open, session close, logout) and
/// 3 privilege (sudo, setuid, setgid). The `execve`, `setresuid`,
/// `CRED_ACQ` and `PROCTITLE` lines are ignored.
#[test]
fn parses_exactly_the_owned_records_out_of_a_realistic_mixed_audit_log() {
    let mut identity = 0;
    let mut privilege = 0;
    for line in fixture_lines() {
        match parse_record(&line) {
            Some(IdentityRecord::Identity(_)) => identity += 1,
            Some(IdentityRecord::Privilege(_)) => privilege += 1,
            None => {}
        }
    }
    assert_eq!(identity, 5, "USER_LOGIN x2, USER_START, USER_END, USER_LOGOUT");
    assert_eq!(privilege, 3, "USER_CMD, setuid, setgid — NOT setresuid");
}

/// The two concurrent sessions in the fixture stay distinct, and the local
/// console login carries no remote address (Global Constraint #9's `?`
/// handling) while the SSH login does — precisely the distinction Task 6's
/// detection rule keys on.
#[test]
fn the_remote_and_local_logins_are_distinguishable_by_remote_addr_alone() {
    let logins: Vec<_> = fixture_lines()
        .iter()
        .filter_map(|l| match parse_record(l) {
            Some(IdentityRecord::Identity(i)) => Some(i),
            _ => None,
        })
        .filter(|i| i.operation == osiris_sensor_api::IdentityOperation::Login)
        .collect();
    assert_eq!(logins.len(), 2);

    let ssh = logins.iter().find(|i| i.session_id == "3").expect("ses=3");
    assert_eq!(ssh.remote_addr.as_deref(), Some("198.51.100.10"));
    assert_eq!(ssh.auth_method.as_deref(), Some("sshd"));
    assert_eq!(ssh.terminal.as_deref(), Some("/dev/pts/0"));

    let console = logins.iter().find(|i| i.session_id == "4").expect("ses=4");
    assert_eq!(console.remote_addr, None, "a tty1 login has no remote address");
    assert_eq!(console.auth_method.as_deref(), Some("login"));
    assert_eq!(console.terminal.as_deref(), Some("tty1"));
}

/// The escalation the whole phase exists to see: pid 300, session 3,
/// acting uid 1000, target uid 0.
#[test]
fn the_fixtures_escalation_reports_a_real_transition_to_root() {
    let escalation = fixture_lines()
        .iter()
        .filter_map(|l| match parse_record(l) {
            Some(IdentityRecord::Privilege(p)) => Some(p),
            _ => None,
        })
        .find(|p| p.operation == osiris_sensor_api::PrivilegeOperation::UidChange)
        .expect("the setuid record must parse");
    assert_eq!(escalation.pid, 300);
    assert_eq!(escalation.ppid, 200);
    assert_eq!(escalation.uid, 1000);
    assert_eq!(escalation.target_uid, Some(0));
    assert_eq!(escalation.session_id.as_deref(), Some("3"));
}
```

`fixture_log.rs` names `IdentityOperation`/`PrivilegeOperation` from `osiris-sensor-api`, which is already a normal dependency of this crate and is therefore linkable from an integration test — **no manifest change is required**. Confirm that by running the test rather than by adding a redundant `[dev-dependencies]` entry.

- [ ] **Step 12: Run the whole crate's tests and the boundary check**

Run: `cargo test -p osiris-sensors-identity`
Expected: PASS — 20 parser tests + 4 sensor tests + 3 fixture-log tests.

Run: `bash tools/check-dep-graph.sh`
Expected: `Dependency-graph check PASSED`, with the new `osiris-sensors-identity` line running for real (no `skip:` line for it).

Run: `cargo build --workspace --all-targets`
Expected: PASS. (Phase 2's retrospective lesson: check the *whole workspace*, not just `-p`-scoped builds — a new workspace member can break a sibling even when its own crate compiles.)

- [ ] **Step 13: Commit**

```bash
git add crates/osiris-sensors/identity Cargo.toml tools/check-dep-graph.sh
git commit -m "feat(sensors): osiris-sensors-identity, the audit-backed Identity sensor

Tails one auditd log with the shared LineTailer and parses two disjoint
record families out of it: USER_LOGIN/LOGOUT/START/END session lifecycle
(RawEvent::Identity) and setuid/setgid SYSCALL plus USER_CMD privilege
transitions (RawEvent::Privilege) — one sensor for both, because §4.3's
catalog has no separate Privilege row and the audit stream carrying USER_*
carries these too.

USER_* lines have two msg= fields, so tokenizing them whole would let the
nested msg='...' overwrite the audit header; split_record separates
header/outer/inner before tokenizing either layer. An unknown address
prints as '?' and becomes None, never a literal question mark; an unset
ses= sentinel drops the record rather than minting an uncorrelatable
session; setresuid/setresgid/capset are ignored rather than guessed at.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01CQ6yt1YUcRLAqQad8DthQc"
```

---

### Task 4: `osiris-storage` + `osiris-storage-sqlite` — session and uid query filters

**Files:**
- Modify: `crates/osiris-storage/src/plan.rs`
- Modify: `crates/osiris-storage-sqlite/src/sqlite_storage.rs`

**Interfaces:**
- Consumes (from Task 2): a `CanonicalEvent` whose `session: Option<SessionRef>` and `user: Option<UserRef>` are actually populated. Nothing before this phase ever populated either, which is why no backfill is needed (Global Constraint #11).
- Produces:
  - `osiris_storage::QueryPlan.session_id: Option<String>` — exact match on `session.session_id`.
  - `osiris_storage::QueryPlan.user_uid: Option<u32>` — exact match on `user.uid`.
  - Two new nullable `events` columns, `session_id TEXT` and `user_uid INTEGER`, plus `idx_events_session_id` and `idx_events_user_uid`.
  - Task 7's `identity_story_handler` composes both filters; Task 8's e2e asserts the stored rows carry them.
- **No `Storage` trait change.** `QueryPlan` is a plain struct with `Default`, so adding two fields breaks no implementor and no caller — verified: the only implementor in the workspace is `SqliteStorage`, and every construction site uses `QueryPlan::new()` or `QueryPlan { .., ..QueryPlan::new() }`.

**Before writing any code**, open `crates/osiris-storage-sqlite/src/sqlite_storage.rs` and confirm the three mechanisms this task extends still look as described: the `CREATE TABLE IF NOT EXISTS events (...)` block that lists every column for a *fresh* database; the `for (column, ddl) in [...]` loop guarded by `column_exists` that migrates an *existing* database; and the second `execute_batch` that creates the per-column indexes after the loop. All three must be edited together — a column added to only one of them produces a database that works on a fresh open and fails on a migrated one (or vice versa), which is exactly what the migration test in Step 6 exists to catch.

- [ ] **Step 1: Write the failing `QueryPlan` test**

Append to `crates/osiris-storage/src/plan.rs`'s `#[cfg(test)] mod tests`, and extend the existing `new_query_plan_defaults_to_limit_100_and_no_filters` test with the two new assertions rather than writing a second near-duplicate test:

```rust
    #[test]
    fn new_query_plan_defaults_the_identity_filters_to_none_too() {
        let plan = QueryPlan::new();
        assert!(plan.session_id.is_none());
        assert!(plan.user_uid.is_none());
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p osiris-storage`
Expected: FAIL to compile — `no field session_id on type QueryPlan`.

- [ ] **Step 3: Add the two filter fields**

In `crates/osiris-storage/src/plan.rs`, insert into `QueryPlan` immediately after the existing `dns_domain` field (keeping the "one doc comment per non-obvious filter" style the existing fields already use):

```rust
    /// Exact-match on `session.session_id`. Because the Enrich stage
    /// attaches the session to every descendant event of a login (Phase 4a
    /// plan Global Constraint #5), this one filter returns the whole
    /// multi-category story for a session — identity, process, privilege,
    /// file and network alike — which is what the Identity Story's
    /// `session_id` form composes.
    pub session_id: Option<String>,
    /// Exact-match on `user.uid`. Deliberately NOT expanded to "every
    /// session this user opened": that fan-out is unbounded for a
    /// long-lived service account and needs §12.3's query planner, which is
    /// Phase 7 (Phase 4a plan Global Constraint #10).
    pub user_uid: Option<u32>,
```

Run: `cargo test -p osiris-storage`
Expected: PASS.

- [ ] **Step 4: Write the failing storage tests**

Append to `crates/osiris-storage-sqlite/src/sqlite_storage.rs`'s `#[cfg(test)] mod tests`. These reuse the module's existing `sample_event`/`open_test_storage` helpers — read them first and confirm `sample_event` still leaves `user`/`session` as `None`, which is what makes the "unattributed events are excluded" assertions meaningful.

```rust
    fn identity_event(
        event_type: osiris_schema::EventType,
        session_id: &str,
        uid: u32,
        remote_addr: Option<&str>,
        timestamp: u64,
    ) -> CanonicalEvent {
        let mut event = sample_event(300, timestamp);
        event.event_type = event_type;
        event.category = event_type.category();
        event.session = Some(osiris_schema::SessionRef {
            session_id: session_id.to_string(),
            tty: Some("/dev/pts/0".to_string()),
            remote_addr: remote_addr.map(str::to_string),
            auth_method: Some("sshd".to_string()),
        });
        event.user = Some(osiris_schema::UserRef {
            uid,
            gid: uid,
            euid: uid,
            egid: uid,
            username: Some("alice".to_string()),
            loginuid: Some(1000),
        });
        event
    }

    #[test]
    fn query_filters_by_session_id_across_every_category() {
        let storage = open_test_storage();
        // The point of the session filter: one id returns the whole
        // multi-category chain, not just the identity events.
        let login = identity_event(
            osiris_schema::EventType::SessionLogin,
            "3",
            0,
            Some("198.51.100.10"),
            1000,
        );
        let escalation = identity_event(
            osiris_schema::EventType::PrivilegeUidChange,
            "3",
            1000,
            Some("198.51.100.10"),
            2000,
        );
        let mut exec = identity_event(
            osiris_schema::EventType::ProcessExec,
            "3",
            1000,
            Some("198.51.100.10"),
            3000,
        );
        exec.category = osiris_schema::Category::Process;
        let other_session = identity_event(
            osiris_schema::EventType::SessionLogin,
            "4",
            0,
            None,
            4000,
        );
        // An event that predates any session attribution at all.
        let unattributed = sample_event(900, 5000);
        storage
            .batch_write(&[
                login.clone(),
                escalation.clone(),
                exec.clone(),
                other_session,
                unattributed,
            ])
            .unwrap();

        let mut plan = QueryPlan::new();
        plan.session_id = Some("3".to_string());
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 3);
        let ids: Vec<_> = results.iter().map(|e| e.event_id).collect();
        assert!(ids.contains(&login.event_id));
        assert!(ids.contains(&escalation.event_id));
        assert!(ids.contains(&exec.event_id));
        // Storage returns rows time-ordered (ORDER BY timestamp ASC).
        assert_eq!(results[0].event_id, login.event_id);
        assert_eq!(results[2].event_id, exec.event_id);
    }

    #[test]
    fn query_filters_by_user_uid() {
        let storage = open_test_storage();
        let root = identity_event(
            osiris_schema::EventType::PrivilegeUidChange,
            "3",
            0,
            Some("198.51.100.10"),
            1000,
        );
        let alice = identity_event(
            osiris_schema::EventType::PrivilegeUidChange,
            "3",
            1000,
            Some("198.51.100.10"),
            2000,
        );
        storage.batch_write(&[root.clone(), alice.clone()]).unwrap();

        let mut plan = QueryPlan::new();
        plan.user_uid = Some(0);
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, root.event_id);

        // uid 0 must not be confused with "no user at all": an event whose
        // `user` is None writes NULL, and NULL never equals 0 in SQL.
        storage.write(&sample_event(901, 3000)).unwrap();
        assert_eq!(storage.query(&plan).unwrap().len(), 1);
    }

    /// The two filters compose (the Identity Story never needs this today,
    /// but the SQL builder must not special-case one over the other).
    #[test]
    fn the_session_and_uid_filters_compose() {
        let storage = open_test_storage();
        let alice_in_3 = identity_event(
            osiris_schema::EventType::PrivilegeUidChange,
            "3",
            1000,
            None,
            1000,
        );
        let root_in_3 = identity_event(
            osiris_schema::EventType::PrivilegeUidChange,
            "3",
            0,
            None,
            2000,
        );
        let alice_in_4 = identity_event(
            osiris_schema::EventType::PrivilegeUidChange,
            "4",
            1000,
            None,
            3000,
        );
        storage
            .batch_write(&[alice_in_3.clone(), root_in_3, alice_in_4])
            .unwrap();

        let mut plan = QueryPlan::new();
        plan.session_id = Some("3".to_string());
        plan.user_uid = Some(1000);
        let results = storage.query(&plan).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, alice_in_3.event_id);
    }

    /// Non-destructive/idempotent migration proof, matching Phase 2 Task 6's
    /// and Phase 3 Task 4's precedent exactly: open a database shaped like it
    /// predates this phase's two new columns, re-open it through the current
    /// `SqliteStorage::open`, and confirm existing data survives, the guarded
    /// ADD COLUMN migration runs, and the new filters work afterwards.
    #[test]
    fn migrates_a_pre_phase_4_database_without_data_loss() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");

        let pre_phase_4_event = sample_event(300, 1000);
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            // A Phase 3 schema: file and network/DNS columns, no identity
            // columns.
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
                    raw_json TEXT NOT NULL
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO events (event_id, host_id, timestamp, event_type, raw_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    pre_phase_4_event.event_id.to_string(),
                    pre_phase_4_event.host_id.to_string(),
                    pre_phase_4_event.timestamp as i64,
                    "PROCESS_EXEC",
                    serde_json::to_string(&pre_phase_4_event).unwrap(),
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

        let login = identity_event(
            osiris_schema::EventType::SessionLogin,
            "3",
            0,
            Some("198.51.100.10"),
            2000,
        );
        reopened.write(&login).unwrap();

        let mut plan = QueryPlan::new();
        plan.session_id = Some("3".to_string());
        assert_eq!(
            reopened.query(&plan).unwrap().len(),
            1,
            "the migrated session_id column must exist and filter correctly"
        );
        let mut plan = QueryPlan::new();
        plan.user_uid = Some(0);
        assert_eq!(
            reopened.query(&plan).unwrap().len(),
            1,
            "the migrated user_uid column must exist and filter correctly"
        );

        // Idempotency: a second open must neither error nor duplicate a
        // column, and everything must still be there and still filterable.
        let reopened_again = SqliteStorage::open(&db_path).unwrap();
        assert_eq!(reopened_again.query(&QueryPlan::new()).unwrap().len(), 2);
        let mut plan = QueryPlan::new();
        plan.session_id = Some("3".to_string());
        assert_eq!(reopened_again.query(&plan).unwrap().len(), 1);
    }
```

- [ ] **Step 5: Run them to verify they fail**

Run: `cargo test -p osiris-storage-sqlite`
Expected: FAIL to compile — `no field session_id` is gone (Step 3 added it), so the failure is now at runtime instead: `no such column: session_id`. Either way the tests must be red before Step 6.

- [ ] **Step 6: Add the two columns, the two indexes, and the two SQL clauses**

Three coordinated edits in `crates/osiris-storage-sqlite/src/sqlite_storage.rs`.

(a) The fresh-database DDL — add both columns to the `CREATE TABLE IF NOT EXISTS events (...)` list, immediately after `dns_domain TEXT,`:

```sql
                session_id TEXT,
                user_uid INTEGER,
```

(b) The migration loop — append two entries to the `for (column, ddl) in [...]` array, and extend the comment above it so the next phase inherits the rationale rather than re-deriving it:

```rust
            ("session_id", "ALTER TABLE events ADD COLUMN session_id TEXT"),
            ("user_uid", "ALTER TABLE events ADD COLUMN user_uid INTEGER"),
```

Extend the existing comment block above the loop with:

```rust
        // Phase 4a adds `session_id` and `user_uid` the same way. As with
        // every earlier phase's columns, pre-existing rows are not
        // backfilled — they read back NULL. That has no practical impact:
        // no database created before Phase 4a can contain an event with a
        // populated `session` or `user`, because nothing populated either
        // field until this phase's pipeline changes.
```

Then add the two indexes to the `execute_batch` that follows the loop:

```sql
             CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
             CREATE INDEX IF NOT EXISTS idx_events_user_uid ON events(user_uid);
```

(c) `batch_write` — extract the two values alongside the existing `dns_domain` extraction, and add them to the INSERT's column list, its placeholder list (`?14`, `?15`) and its `params!`:

```rust
            let session_id = event.session.as_ref().map(|s| s.session_id.clone());
            // i64 because SQLite has no unsigned integer type; a uid is at
            // most u32::MAX, so this widening is always lossless — the same
            // cast the file inode/device columns already use.
            let user_uid = event.user.as_ref().map(|u| u.uid as i64);
```

The INSERT becomes:

```rust
                    "INSERT OR IGNORE INTO events (event_id, host_id, timestamp, event_type, process_key, parent_process_key, file_path, file_inode, file_device_id, network_src_ip, network_dst_ip, dns_domain, session_id, user_uid, raw_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
```

with `session_id, user_uid,` inserted into `params![...]` immediately before `raw_json`. **Keep `raw_json` last** — the placeholder numbering is positional, and moving it silently corrupts every write.

(d) `query` — add the two clauses after the existing `dns_domain` clause and before the `since`/`until` clauses (order within the `WHERE` chain is irrelevant to SQLite, but keeping the filter order identical to `QueryPlan`'s field order is what makes the builder auditable at a glance):

```rust
        if let Some(session_id) = &plan.session_id {
            sql.push_str(" AND session_id = ?");
            sql_params.push(Box::new(session_id.clone()));
        }
        if let Some(uid) = plan.user_uid {
            sql.push_str(" AND user_uid = ?");
            sql_params.push(Box::new(uid as i64));
        }
```

- [ ] **Step 7: Run the whole crate's tests**

Run: `cargo test -p osiris-storage -p osiris-storage-sqlite`
Expected: PASS — every pre-existing storage test (in particular the Phase 2 and Phase 3 migration tests, which must still pass unchanged) plus the four new ones.

Run: `cargo build --workspace --all-targets`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/osiris-storage crates/osiris-storage-sqlite
git commit -m "feat(storage): session_id and user_uid query filters

Two nullable indexed columns added through the existing column_exists-
guarded ALTER TABLE loop, so a Phase 1/2/3 database migrates in place
without data loss and a second open is a no-op. Pre-existing rows read
back NULL and are not backfilled — nothing before Phase 4a ever populated
CanonicalEvent.session or .user.

The session filter is what makes an Identity Story genuinely
multi-category: Enrich attaches the session to every descendant event of a
login, so one session id returns identity, process, privilege, file and
network events together.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01CQ6yt1YUcRLAqQad8DthQc"
```

---

### Task 5: `generator` + `osiris-agent` — the SSH/sudo escalation scenario and wiring `IdentitySensor` into the Agent

**Files:**
- Modify: `generator/src/scenarios.rs`
- Modify: `crates/osiris-agent/src/config.rs`
- Modify: `crates/osiris-agent/src/agent.rs`
- Modify: `crates/osiris-agent/Cargo.toml`

**Interfaces:**
- Consumes: Task 1's `IdentityEventRaw`/`PrivilegeEventRaw` and Task 3's `IdentitySensor`.
- Produces:
  - `osiris_generator::scenarios::ssh_sudo_escalation_scenario(base_ts_ns: u64) -> Vec<RawEvent>` plus the constants `SSH_SESSION_ID`, `SSH_REMOTE_ADDR`, `ROOT_KEYS_PATH`, `ESCALATION_C2_IP`.
  - `AgentConfig.identity_audit_log_path: Option<String>` (serde `default`, so every existing Phase 1/2/3 `agent.yaml` still loads).
  - `synthetic_scenario: Some("ssh_sudo_escalation")` selects the new scenario.
  - Task 8's e2e test drives the Agent with exactly this config.

**Before writing any code**, read `generator/src/scenarios.rs`'s private `exec` and `file_event` helpers and confirm their signatures (`exec(pid, ppid, exe_path, comm, timestamp_ns)`; `file_event(operation, path, previous_path, inode, pid, ppid, exe_path, comm, timestamp_ns)`), and read `crates/osiris-agent/src/agent.rs`'s `Agent::start` to confirm the `candidate_sensors` construction and the `match config.synthetic_scenario.as_deref()` dispatch are still shaped as this task assumes. Both are load-bearing here.

- [ ] **Step 1: Write the failing scenario tests**

Append to `generator/src/scenarios.rs`'s `#[cfg(test)] mod tests`:

```rust
    fn identity_raw_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::IdentityEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::Identity(i) => Some(i),
                _ => None,
            })
            .collect()
    }

    fn privilege_raw_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::PrivilegeEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::Privilege(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    /// ARCHITECTURE.md §26's worked trace, now from its actual first step:
    /// sshd accepts a connection, PAM/audit records the session, a shell
    /// runs inside it, sudo escalates to root, and the escalated process
    /// then touches the filesystem and the network — so the resulting
    /// stored chain spans IDENTITY, PROCESS, PRIVILEGE, FILE and NETWORK,
    /// all under one session id.
    #[test]
    fn ssh_sudo_escalation_scenario_spans_all_five_categories_under_one_session() {
        let scenario = ssh_sudo_escalation_scenario(1_000_000_000);
        assert_eq!(scenario.len(), 9);

        let identity = identity_raw_events(&scenario);
        assert_eq!(identity.len(), 2, "one login, one logout");
        assert_eq!(identity[0].operation, osiris_sensor_api::IdentityOperation::Login);
        assert_eq!(identity[0].session_id, SSH_SESSION_ID);
        assert_eq!(identity[0].remote_addr.as_deref(), Some(SSH_REMOTE_ADDR));
        assert_eq!(identity[0].auth_method.as_deref(), Some("sshd"));
        assert_eq!(identity[0].pid, 100, "the login is rooted at sshd's pid");
        assert_eq!(
            identity[1].operation,
            osiris_sensor_api::IdentityOperation::Logout
        );

        assert_eq!(exec_events(&scenario).len(), 3, "sshd, bash, sudo");

        let privilege = privilege_raw_events(&scenario);
        assert_eq!(privilege.len(), 2, "one sudo invocation, one uid change");
        assert_eq!(privilege[0].operation, osiris_sensor_api::PrivilegeOperation::Sudo);
        assert_eq!(privilege[1].operation, osiris_sensor_api::PrivilegeOperation::UidChange);
        assert_eq!(privilege[1].uid, 1000);
        assert_eq!(privilege[1].target_uid, Some(0), "escalation to root");

        assert_eq!(file_events(&scenario).len(), 1);
        assert_eq!(file_events(&scenario)[0].path, ROOT_KEYS_PATH);
        assert_eq!(network_raw_events(&scenario).len(), 1);
        assert_eq!(network_raw_events(&scenario)[0].remote_addr, ESCALATION_C2_IP);
    }

    /// The escalating process must be a descendant of the login's pid, or
    /// the Enrich stage's ppid-inheritance chain cannot reach it and the
    /// whole phase's correlation silently produces nothing.
    #[test]
    fn every_post_login_actor_descends_from_the_logins_pid() {
        let scenario = ssh_sudo_escalation_scenario(1_000_000_000);
        let execs = exec_events(&scenario);
        assert_eq!((execs[0].pid, execs[0].ppid), (100, 1), "sshd");
        assert_eq!((execs[1].pid, execs[1].ppid), (200, 100), "bash under sshd");
        assert_eq!((execs[2].pid, execs[2].ppid), (300, 200), "sudo under bash");

        let escalation = privilege_raw_events(&scenario)[1];
        assert_eq!((escalation.pid, escalation.ppid), (300, 200));
        // The file and network events name pid 300, which by then is a
        // known session member via its own exec.
        assert_eq!(file_events(&scenario)[0].pid, 300);
        assert_eq!(network_raw_events(&scenario)[0].pid, Some(300));
    }

    /// The logout is last, so it cannot prune the session before the events
    /// that must inherit it are processed.
    #[test]
    fn ssh_sudo_escalation_scenario_is_strictly_time_ordered_and_ends_with_the_logout() {
        let scenario = ssh_sudo_escalation_scenario(1_000_000_000);
        let timestamps: Vec<u64> = scenario.iter().map(RawEvent::timestamp_ns).collect();
        let mut sorted = timestamps.clone();
        sorted.sort();
        assert_eq!(timestamps, sorted);
        assert!(timestamps.windows(2).all(|w| w[0] < w[1]));
        assert!(matches!(scenario.last(), Some(RawEvent::Identity(i)) if i.operation
            == osiris_sensor_api::IdentityOperation::Logout));
    }
```

Also extend the module's existing `every_scenario_is_strictly_time_ordered` test's scenario list with `ssh_sudo_escalation_scenario(1_000_000_000)` — read that test first; it iterates a slice of scenarios, and the new one belongs in it.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p osiris-generator`
Expected: FAIL to compile — `cannot find function ssh_sudo_escalation_scenario`, `cannot find value SSH_SESSION_ID`.

- [ ] **Step 3: Implement the scenario**

In `generator/src/scenarios.rs`, extend the `use` block:

```rust
use osiris_sensor_api::{
    DnsEventRaw, FileEventRaw, FileOperation, IdentityEventRaw, IdentityOperation, NetworkDirection,
    NetworkEventRaw, NetworkOperation, PrivilegeEventRaw, PrivilegeOperation, ProcessExecRaw,
    RawEvent, RawEventSource,
};
```

Add the constants next to the existing scenario constants:

```rust
/// The audit session id the whole Phase 4a chain hangs off. A string, not
/// an integer, because §9.2's `SessionRef.session_id` is one.
pub const SSH_SESSION_ID: &str = "3";
/// The address the session was opened from — what makes Task 6's rule
/// able to say "a remote session" rather than "any escalation".
pub const SSH_REMOTE_ADDR: &str = "198.51.100.10";
/// What the escalated process writes: the canonical post-escalation
/// persistence touch, and a FILE-category event under the same session.
pub const ROOT_KEYS_PATH: &str = "/root/.ssh/authorized_keys";
const ROOT_KEYS_INODE: u64 = 400_555;
/// Where it then connects — a NETWORK-category event under the same
/// session, completing §26's identity->process->file->network chain.
pub const ESCALATION_C2_IP: &str = "203.0.113.77";
```

Append the scenario function after `network_beacon_scenario`:

```rust
/// ARCHITECTURE.md §26's worked trace from its true first step: sshd
/// accepts a remote connection, audit records the login, a shell runs
/// inside that session, sudo escalates it to root, and the escalated
/// process writes root's authorized_keys and then calls out to a remote
/// address. Nine events spanning all five categories this codebase can
/// produce, every one of them under session id `SSH_SESSION_ID` once the
/// Enrich stage's `SessionResolver` has propagated it (Phase 4a plan
/// Global Constraint #5).
///
/// The logout is deliberately last: `SESSION_LOGOUT` prunes the session
/// from the resolver, so an earlier placement would leave every subsequent
/// event unattributed — which is correct behaviour, and exactly why the
/// ordering matters here.
pub fn ssh_sudo_escalation_scenario(base_ts_ns: u64) -> Vec<RawEvent> {
    vec![
        exec(100, 1, "/usr/sbin/sshd", "sshd", base_ts_ns),
        RawEvent::Identity(IdentityEventRaw {
            operation: IdentityOperation::Login,
            session_id: SSH_SESSION_ID.to_string(),
            pid: 100,
            // sshd authenticates as root; the user who logged in is `auid`.
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
            // USER_CMD carries no ppid — 0 is the "no parent reported"
            // convention, and the resolver still attributes this event
            // because pid 300 is already a known session member from its
            // own exec above.
            ppid: 0,
            uid: 1000,
            gid: None,
            euid: None,
            egid: None,
            auid: Some(1000),
            session_id: Some(SSH_SESSION_ID.to_string()),
            username: None,
            // Global Constraint #9: USER_CMD does not reliably report the
            // target account, so the synthetic record does not invent one
            // either — the generator must produce records the real sensor
            // could actually have produced.
            target_uid: None,
            target_gid: None,
            command: Some("/usr/bin/tee /root/.ssh/authorized_keys".to_string()),
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
        file_event(
            FileOperation::Write,
            ROOT_KEYS_PATH,
            None,
            ROOT_KEYS_INODE,
            300,
            200,
            "/usr/bin/sudo",
            "sudo",
            base_ts_ns + 6_000_000,
        ),
        RawEvent::Network(NetworkEventRaw {
            operation: NetworkOperation::Connect,
            local_addr: "10.0.0.5".to_string(),
            local_port: 51001,
            remote_addr: ESCALATION_C2_IP.to_string(),
            remote_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            pid: Some(300),
            uid: 0,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: base_ts_ns + 7_000_000,
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
            audit_serial: Some(513),
            source: RawEventSource::Synthetic,
        }),
    ]
}
```

Note the deliberate asymmetry with `web_shell_drop_scenario`: this scenario writes to `/root/.ssh/authorized_keys`, not into `/var/www/`, so Phase 2's `shell_wrote_file_to_web_root` rule must NOT fire on it, and it connects to a bare IP with no DNS query, so Phase 3's `dns_query_to_suspicious_tld` rule must not fire either. Exactly one alert — Task 6's — is expected from this scenario, and Task 8 asserts that.

- [ ] **Step 4: Run the scenario tests to verify they pass**

Run: `cargo test -p osiris-generator`
Expected: PASS — every existing scenario test plus the three new ones.

- [ ] **Step 5: Write the failing Agent-wiring tests**

Append to `crates/osiris-agent/src/config.rs`'s `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn the_new_phase_4a_field_defaults_to_none_so_earlier_configs_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "enable_synthetic: true\nspool_path: /tmp/spool.ndjson\nstatus_addr: 127.0.0.1:9200\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(config.identity_audit_log_path.is_none());
    }

    #[test]
    fn loads_an_identity_audit_log_path_when_one_is_configured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "enable_synthetic: false\nidentity_audit_log_path: /var/log/audit/audit.log\n\
             spool_path: /tmp/spool.ndjson\nstatus_addr: 127.0.0.1:9200\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert_eq!(
            config.identity_audit_log_path.as_deref(),
            Some("/var/log/audit/audit.log")
        );
    }
```

Append to `crates/osiris-agent/src/agent.rs`'s `#[cfg(test)] mod tests` (mirroring the existing `fs_audit_log_path` skip/start tests — read them first and follow their exact construction of `AgentConfig` and their `shutdown()` discipline):

```rust
    #[tokio::test]
    async fn the_identity_sensor_is_skipped_with_a_reason_when_its_log_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(&dir);
        config.enable_synthetic = false;
        config.identity_audit_log_path =
            Some(dir.path().join("missing.log").to_string_lossy().to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let skipped = agent.skipped_sensors();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].name, "identity");
        assert!(skipped[0].reason.contains("audit log not found"));
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn the_identity_sensor_starts_when_its_log_exists() {
        let dir = tempfile::tempdir().unwrap();
        let identity_log = dir.path().join("identity-audit.log");
        std::fs::write(&identity_log, "").unwrap();
        let mut config = test_config(&dir);
        config.enable_synthetic = false;
        config.identity_audit_log_path =
            Some(identity_log.to_string_lossy().to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status().await;
        assert_eq!(status.sensors.len(), 1);
        assert_eq!(status.sensors[0].name, "identity");
        assert!(status.skipped_sensors.is_empty());
        agent.shutdown().await;
    }

    /// The scenario selector must reach the new scenario; an unknown name
    /// still falls back to exec_chain with a warning, unchanged.
    #[tokio::test]
    async fn the_ssh_sudo_escalation_scenario_is_selectable() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("ssh_sudo_escalation".to_string());
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        agent.shutdown().await;

        let spool = std::fs::read_to_string(dir.path().join("spool.ndjson")).unwrap();
        let lines: Vec<&str> = spool.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 9, "all nine scenario events must reach the spool");
        let categories: std::collections::HashSet<String> = lines
            .iter()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["category"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        for expected in ["IDENTITY", "PROCESS", "PRIVILEGE", "FILE", "NETWORK"] {
            assert!(categories.contains(expected), "missing category {expected}");
        }
    }
```

If `test_config`/`test_host` helpers do not exist under those names in that module, use whatever the existing `fs_audit_log_path` tests use — read them and follow, do not invent new helpers. The three tests above also need `serde_json` as an `osiris-agent` dev-dependency if it is not already a normal one; `osiris-agent`'s manifest does not currently list it, so add `serde_json = { workspace = true }` under `[dev-dependencies]` rather than promoting it to a normal dependency.

- [ ] **Step 6: Run them to verify they fail**

Run: `cargo test -p osiris-agent`
Expected: FAIL to compile — `no field identity_audit_log_path on type AgentConfig`.

- [ ] **Step 7: Wire the sensor and the scenario into the Agent**

In `crates/osiris-agent/Cargo.toml`, add the dependency after the three existing sensor crates:

```toml
osiris-sensors-identity = { path = "../osiris-sensors/identity" }
```

and, if absent, `serde_json = { workspace = true }` under `[dev-dependencies]`.

In `crates/osiris-agent/src/config.rs`, add the field after `network_proc_root`:

```rust
    /// Path to a Linux auditd-style log file for the Identity sensor's
    /// audit backend, carrying `USER_*`, `USER_CMD` and `setuid`/`setgid`
    /// `SYSCALL` records (Phase 4a plan Global Constraints #2/#4). A
    /// separate key from `audit_log_path`/`fs_audit_log_path` so an
    /// operator can point each sensor at its own rule-scoped log; pointing
    /// several of them at the same file is equally valid, because each
    /// sensor ignores the records the others consume. Skipped, never
    /// silently, if absent or non-existent.
    #[serde(default)]
    pub identity_audit_log_path: Option<String>,
```

and extend the `synthetic_scenario` doc comment's scenario list with `` `"ssh_sudo_escalation"` (§26's trace from its first step: login, shell, sudo escalation, file write, outbound connection) ``.

In `crates/osiris-agent/src/agent.rs`, add the import:

```rust
use osiris_sensors_identity::IdentitySensor;
```

extend the generator import to include `ssh_sudo_escalation_scenario`, add the candidate-sensor block after the `network_proc_root` block:

```rust
        if let Some(path) = &config.identity_audit_log_path {
            candidate_sensors.push(Box::new(IdentitySensor::new(path.clone())));
        }
```

and add the scenario arm to the existing `match config.synthetic_scenario.as_deref()`, before the `Some("exec_chain") | None` arm:

```rust
                Some("ssh_sudo_escalation") => ssh_sudo_escalation_scenario(base_ts),
```

Nothing else in the Agent changes: the supervisor loop, the capability-driven skip path, the spool writer and the pipeline call are all category-agnostic and already handle any `RawEvent` variant.

- [ ] **Step 8: Run the Agent tests**

Run: `cargo test -p osiris-agent`
Expected: PASS — every existing Agent test plus the five new ones.

Run: `bash tools/check-dep-graph.sh`
Expected: `Dependency-graph check PASSED` — `osiris-agent` may depend on a sensor crate (that is the whole point of §27's split); the forbidden direction is a sensor reaching the Server/API, which Task 3's line already checks.

Run: `cargo build --workspace --all-targets && cargo test --workspace`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add generator crates/osiris-agent
git commit -m "feat(generator,agent): the ssh_sudo_escalation scenario and IdentitySensor wiring

A nine-event scenario covering ARCHITECTURE.md §26's trace from its true
first step — sshd login, shell, sudo, escalation to root, a write to
root's authorized_keys, and an outbound connection — spanning IDENTITY,
PROCESS, PRIVILEGE, FILE and NETWORK under one session id. The logout is
last, because SESSION_LOGOUT prunes the session from the resolver.

The Agent gains identity_audit_log_path (serde default, so every existing
agent.yaml still loads) and starts IdentitySensor from it, skipped with a
reason when the log is absent — never silently.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01CQ6yt1YUcRLAqQad8DthQc"
```

---

### Task 6: `config/rules` — the third shipped detection rule (privilege escalation to root inside a remote session)

**Files:**
- Create: `config/rules/privilege_escalation_to_root_in_remote_session.yaml`
- Modify: `crates/osiris-detect/src/engine.rs` (tests only)

**Interfaces:**
- Consumes: the `CanonicalEvent` JSON projection Task 2 produces — specifically `event_type`, `event_data.target_uid` and `session.remote_addr`.
- Produces: a third rule loaded by the existing `DetectionEngine::load_from_dir(config/rules)` scan, firing as `rule_id: privilege_escalation_to_root_in_remote_session`.
- Task 8's e2e asserts this rule — and only this rule — fires on the `ssh_sudo_escalation` scenario.

**No `osiris-detect` source changes (Global Constraint #13) — and this task must verify that claim against the real code before writing the rule, not assume it from the constraint's prose.** Open `crates/osiris-detect/src/eval.rs` and `crates/osiris-detect/src/engine.rs` and confirm all four of the following. If any is false, **stop and report it**, because the rule below silently depends on every one of them:

1. `eval::field_value` splits the rule's `field` on `.` and walks the serialized event with `current.get(segment)?` — so `session.remote_addr` and `event_data.target_uid` resolve with no new code, because `CanonicalEvent` serializes `session` and `event_data` under exactly those JSON names (verified against `crates/osiris-schema/src/envelope.rs`).
2. `eval::field_value` returns `None` for an explicit JSON `null`, not `Some(Value::Null)` — its own test `returns_none_for_a_missing_or_null_field` asserts this. That is what makes a condition on `session.remote_addr` double as an existence check: an event with no session, or a session whose `remote_addr` is `null`, resolves to `None`.
3. `engine::evaluate_rule` short-circuits the whole rule on such a field: `let actual = field_value(event_json, &condition.field)?;` returns `None` from `evaluate_rule`, so a missing field is a non-match rather than a `null == expected` comparison. A local console escalation therefore cannot fire this rule.
4. `DetectionEngine::load_from_dir` globs `*.yaml`/`*.yml`, sorts by file name, and constructs a `Rule` per file — so a third file is picked up with no registration step anywhere.

Also confirm the rule *schema* the file must satisfy, from `crates/osiris-detect/src/rule.rs`: `RuleFile` is `#[serde(deny_unknown_fields)]` with exactly `id`, `version`, `severity`, `match`; every `Condition` requires `field`, `op`, `value` **and a non-blank `reason`**; and `Operator` is exactly `{eq, ne, contains, starts_with, ends_with, in}` — there is no `exists`, no `gt`/`lt` and no regex. That operator set is why the "session has a remote address" condition is written as `ne ""` rather than as an existence test: given point 2 above, `ne ""` matches exactly when the field is present and non-empty.

- [ ] **Step 1: Write the failing rule tests**

Append to `crates/osiris-detect/src/engine.rs`'s `#[cfg(test)] mod tests`. Read the module's existing `dns_event` helper first — this one follows its shape exactly, differing only in which entity refs it populates.

```rust
    fn escalation_event(
        event_type: EventType,
        target_uid: Option<u32>,
        remote_addr: Option<&str>,
    ) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        let mut event = event(event_type, "/unused", "/usr/bin/sudo");
        event.host_id = host_id;
        event.category = event_type.category();
        event.file = None;
        event.user = Some(osiris_schema::UserRef {
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
            username: Some("alice".to_string()),
            loginuid: Some(1000),
        });
        event.session = Some(osiris_schema::SessionRef {
            session_id: "3".to_string(),
            tty: Some("/dev/pts/0".to_string()),
            remote_addr: remote_addr.map(str::to_string),
            auth_method: Some("sshd".to_string()),
        });
        event.event_data = serde_json::json!({
            "comm": "sudo",
            "ppid": 200,
            "uid": 1000,
            "target_uid": target_uid,
            "target_gid": serde_json::Value::Null,
            "success": true,
        });
        event
    }

    #[test]
    fn the_shipped_privilege_escalation_rule_loads_and_fires_on_its_positive_fixture_only() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/rules/privilege_escalation_to_root_in_remote_session.yaml");
        let yaml = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
        let engine = DetectionEngine::new(vec![Rule::from_yaml_str(
            &yaml,
            "privilege_escalation_to_root_in_remote_session.yaml",
        )
        .expect("the shipped rule must parse")]);

        // Positive: a real escalation to root inside an SSH session.
        let alerts = engine.evaluate(&escalation_event(
            EventType::PrivilegeUidChange,
            Some(0),
            Some("198.51.100.10"),
        ));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id(), "privilege_escalation_to_root_in_remote_session");
        assert_eq!(alerts[0].severity(), Severity::High);
        // §11.2's structural requirement: one specific explanation per
        // matched condition, none of them blank or generic.
        let reasons = alerts[0].reasons();
        assert_eq!(reasons.len(), 3);
        assert!(reasons.iter().all(|r| !r.trim().is_empty()));
        assert!(reasons.iter().any(|r| r.contains("root")));
        assert!(reasons.iter().any(|r| r.contains("remote")));
    }

    /// The negative the whole rule turns on: the same escalation, from a
    /// local console session with no remote address, must NOT fire. This is
    /// what stops the rule alerting on every `sudo` a sysadmin runs at the
    /// keyboard — and it works because `field_value` maps a null
    /// `session.remote_addr` to `None` and `evaluate_rule` short-circuits.
    #[test]
    fn the_privilege_escalation_rule_does_not_fire_on_a_local_escalation() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/rules/privilege_escalation_to_root_in_remote_session.yaml");
        let yaml = std::fs::read_to_string(&path).unwrap();
        let engine = DetectionEngine::new(vec![
            Rule::from_yaml_str(&yaml, "privilege_escalation.yaml").unwrap()
        ]);

        // No remote address at all (a tty1 login).
        assert!(engine
            .evaluate(&escalation_event(EventType::PrivilegeUidChange, Some(0), None))
            .is_empty());

        // No session whatsoever (a daemon escalating outside any login).
        let mut sessionless = escalation_event(EventType::PrivilegeUidChange, Some(0), None);
        sessionless.session = None;
        assert!(engine.evaluate(&sessionless).is_empty());
    }

    #[test]
    fn the_privilege_escalation_rule_does_not_fire_on_a_non_root_or_non_uid_transition() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/rules/privilege_escalation_to_root_in_remote_session.yaml");
        let yaml = std::fs::read_to_string(&path).unwrap();
        let engine = DetectionEngine::new(vec![
            Rule::from_yaml_str(&yaml, "privilege_escalation.yaml").unwrap()
        ]);

        // Escalating to a non-root account is not this rule's concern.
        assert!(engine
            .evaluate(&escalation_event(
                EventType::PrivilegeUidChange,
                Some(48),
                Some("198.51.100.10")
            ))
            .is_empty());

        // A gid change to gid 0 is not a uid escalation, and Task 2 never
        // puts a target_uid on one.
        assert!(engine
            .evaluate(&escalation_event(
                EventType::PrivilegeGidChange,
                None,
                Some("198.51.100.10")
            ))
            .is_empty());

        // A sudo invocation carries no reliable target account (Global
        // Constraint #9), so `event_data.target_uid` is null and the rule
        // must not fire on it — the rule detects the transition, not the
        // intent to make one.
        assert!(engine
            .evaluate(&escalation_event(
                EventType::PrivilegeSudo,
                None,
                Some("198.51.100.10")
            ))
            .is_empty());
    }

    /// All three shipped rules must load together and stay independent as
    /// `config/rules/` grows — the same guard Phase 3 added for two.
    #[test]
    fn all_three_shipped_rules_load_together_without_cross_firing() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
        let engine = DetectionEngine::load_from_dir(&dir).unwrap();
        assert!(engine.rule_count() >= 3);

        let alerts = engine.evaluate(&escalation_event(
            EventType::PrivilegeUidChange,
            Some(0),
            Some("198.51.100.10"),
        ));
        assert_eq!(
            alerts.len(),
            1,
            "an escalation event must fire exactly the escalation rule — neither the \
             web-root file rule nor the DNS rule"
        );
        assert_eq!(alerts[0].rule_id(), "privilege_escalation_to_root_in_remote_session");
    }
```

Read `Alert`'s accessors (`rule_id()`, `severity()`, `reasons()`) in `crates/osiris-schema/src/` before relying on the exact names above; the module's existing rule tests already call some of them, so follow those call sites rather than these if they differ.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p osiris-detect`
Expected: FAIL — `could not read .../privilege_escalation_to_root_in_remote_session.yaml`, and `all_three_shipped_rules_load_together_without_cross_firing` fails its `rule_count() >= 3` assertion.

- [ ] **Step 3: Write the rule**

Create `config/rules/privilege_escalation_to_root_in_remote_session.yaml`:

```yaml
# Detects a process gaining root inside a session that was opened from a
# remote address — the SSH-session-to-root escalation ARCHITECTURE.md §26's
# worked trace opens with, and the shape Phase 4a exists to make
# expressible. Neither half is suspicious alone: escalation to root happens
# on every host constantly (every `sudo` at a local console, every
# daemon dropping and regaining privilege), and remote sessions are
# ordinary. It is the conjunction — a remotely-authenticated session that
# becomes root — that is worth an analyst's attention, which is the same
# "actor plus artifact, not artifact alone" shape that keeps Phase 2's
# shell_wrote_file_to_web_root and Phase 3's dns_query_to_suspicious_tld
# specific rather than noisy (ARCHITECTURE.md §11.2).
#
# The `session.remote_addr` condition is written as `ne ""` deliberately:
# the operator set has no existence test, but `eval::field_value` maps a
# missing-or-null field to None and `engine::evaluate_rule` treats that as a
# non-match, so `ne ""` matches exactly when the field is present and
# non-empty. A local console login (auditd prints `addr=?`, which the
# Identity sensor maps to None) therefore cannot match this rule.
#
# This rule reads `event_data.target_uid`, which only PRIVILEGE_UID_CHANGE
# carries: PRIVILEGE_GID_CHANGE reports target_gid instead, and
# PRIVILEGE_SUDO reports no target at all because auditd's USER_CMD record
# does not reliably name one (Phase 4a plan Global Constraint #9). Both are
# therefore non-matches by construction, not by an extra exclusion clause.
#
# MITRE ATT&CK: T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo
# Caching), reached over T1021.004 (Remote Services: SSH).
id: privilege_escalation_to_root_in_remote_session
version: 1
severity: HIGH
match:
  - field: event_type
    op: eq
    value: "PRIVILEGE_UID_CHANGE"
    reason: "A process changed its real uid via setuid(2), a completed privilege transition rather than an attempt"
  - field: event_data.target_uid
    op: eq
    value: 0
    reason: "The uid it transitioned to is 0 (root), so the process now holds full administrative privilege"
  - field: session.remote_addr
    op: ne
    value: ""
    reason: "The escalating process belongs to a session opened from a remote network address (an SSH login), not a local console or an unattributed system service"
```

- [ ] **Step 4: Run the detect tests to verify they pass**

Run: `cargo test -p osiris-detect`
Expected: PASS — every existing rule/eval/engine test plus the four new ones.

If `the_shipped_privilege_escalation_rule_loads_and_fires_on_its_positive_fixture_only` fails on the `target_uid` condition specifically, the cause is a `serde_json::Number` representation mismatch between the YAML-parsed `0` and the event's serialized `0`; both are non-negative and therefore both land in `Number`'s `PosInt(u64)` arm, so this should not occur — but if it does, **do not** work around it by loosening the rule (e.g. dropping the condition or switching to a string comparison). Report it: it would mean the rule language cannot express numeric equality, which is a `osiris-detect` defect worth fixing properly rather than a rule-authoring problem.

- [ ] **Step 5: Confirm no `osiris-detect` source file changed**

Run: `git status --short crates/osiris-detect`
Expected: exactly one modified file, `crates/osiris-detect/src/engine.rs`, and `git diff crates/osiris-detect` must show changes **only inside its `#[cfg(test)] mod tests` block**. Global Constraint #13 asserts this phase adds a rule without touching the engine; if any non-test line changed, the constraint has been violated and the change must be justified or reverted.

- [ ] **Step 6: Commit**

```bash
git add config/rules crates/osiris-detect
git commit -m "feat(rules): ship the privilege-escalation-to-root-in-a-remote-session rule

Fires on PRIVILEGE_UID_CHANGE with target_uid 0 where the event's session
carries a remote address — the SSH-session-to-root escalation §26's trace
opens with. Neither half is suspicious alone; the conjunction is.

Zero osiris-detect source changes: field_value's dotted-path resolution
already reaches session.remote_addr and event_data.target_uid, and its
missing-or-null-is-a-non-match rule is what lets 'ne \"\"' serve as the
existence test the operator set has no keyword for. Proven by tests for a
remote escalation firing, and a local one, a non-root target, a gid change
and a sudo record all not firing.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01CQ6yt1YUcRLAqQad8DthQc"
```

---

### Task 7: `osiris-api` — `GET /api/v1/identity/story`

**Files:**
- Modify: `crates/osiris-api/src/lib.rs`

**Interfaces:**
- Consumes: Task 4's `QueryPlan.session_id`/`QueryPlan.user_uid`, plus the existing `Storage::query`/`Storage::query_alerts` surface. No new `Storage` method.
- Produces:
  - Route `GET /api/v1/identity/story?session_id=…` or `?uid=…`.
  - `IdentityStoryQuery { session_id: Option<String>, uid: Option<u32> }` and `IdentityStory { events: Vec<CanonicalEvent>, alerts: Vec<Alert> }` — deliberately the same `{ events, alerts }` response shape as `FileStory` and `NetworkStory`, so a Console rendering one renders all three (Global Constraint #10 carries the precedent forward rather than reinventing it).
- No `osiris-server` change and no `osiris-cli` verb (Global Constraint #14).

**Before writing any code**, read `crates/osiris-api/src/lib.rs`'s `network_story_handler` and `file_story_handler` end to end and confirm the five conventions this task mirrors exactly, rather than assuming them: (1) the handler takes `State(storage): State<Arc<dyn Storage>>` and `Query(q): Query<…>`; (2) it returns `Result<Json<…>, (StatusCode, String)>` and returns `StatusCode::BAD_REQUEST` with a plain-string body when no lookup parameter is given; (3) all storage work happens inside one `tokio::task::spawn_blocking(move || { … })` closure that returns `Ok::<_, osiris_storage::StorageError>((events, alerts))`, whose `.await.unwrap()` is then `map_err`'d to `INTERNAL_SERVER_ERROR`; (4) results are de-duplicated through a `HashMap<uuid::Uuid, CanonicalEvent>` and then sorted by `(timestamp, event_id)`; (5) alerts are fetched in one `AlertQueryPlan` with `evidence_event_ids` set to every returned event id, skipped entirely when that list is empty, with `limit = 10_000`. `GET /api/v1/users` from §14.2's listing surface is **not** added (Global Constraint #10).

- [ ] **Step 1: Write the failing handler tests**

Append to `crates/osiris-api/src/lib.rs`'s `#[cfg(test)] mod tests`. Read the existing `network_event`/`dns_event`/`sample_alert`/`test_storage` helpers first and follow their construction style.

```rust
    fn session_event(
        event_type: EventType,
        session_id: &str,
        uid: u32,
        remote_addr: Option<&str>,
        timestamp: u64,
    ) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type,
            category: event_type.category(),
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: Some(osiris_schema::UserRef {
                uid,
                gid: uid,
                euid: uid,
                egid: uid,
                username: Some("alice".to_string()),
                loginuid: Some(1000),
            }),
            session: Some(osiris_schema::SessionRef {
                session_id: session_id.to_string(),
                tty: Some("/dev/pts/0".to_string()),
                remote_addr: remote_addr.map(str::to_string),
                auth_method: Some("sshd".to_string()),
            }),
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "b", 300, timestamp),
                pid: 300,
                exe_path: "/usr/bin/sudo".to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: timestamp,
            }),
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[tokio::test]
    async fn identity_story_returns_400_when_neither_param_given() {
        let (_dir, storage) = test_storage();
        let result = identity_story_handler(
            State(storage),
            Query(IdentityStoryQuery {
                session_id: None,
                uid: None,
            }),
        )
        .await;
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    /// Global Constraint #10's session form: because Enrich attaches the
    /// session to every descendant event, one session id returns the whole
    /// multi-category chain, time-ordered, plus every citing alert.
    #[tokio::test]
    async fn identity_story_by_session_returns_the_whole_multi_category_chain() {
        let (_dir, storage) = test_storage();
        let login = session_event(EventType::SessionLogin, "3", 0, Some("198.51.100.10"), 1000);
        let exec = session_event(EventType::ProcessExec, "3", 1000, Some("198.51.100.10"), 2000);
        let escalation = session_event(
            EventType::PrivilegeUidChange,
            "3",
            1000,
            Some("198.51.100.10"),
            3000,
        );
        let other_session = session_event(EventType::SessionLogin, "4", 0, None, 4000);
        storage
            .batch_write(&[
                login.clone(),
                exec.clone(),
                escalation.clone(),
                other_session,
            ])
            .unwrap();
        storage
            .write_alerts(&[sample_alert(
                "privilege_escalation_to_root_in_remote_session",
                vec![escalation.event_id],
                3000,
            )])
            .unwrap();

        let Json(story) = identity_story_handler(
            State(storage),
            Query(IdentityStoryQuery {
                session_id: Some("3".to_string()),
                uid: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(story.events.len(), 3);
        assert_eq!(story.events[0].event_id, login.event_id);
        assert_eq!(story.events[1].event_id, exec.event_id);
        assert_eq!(story.events[2].event_id, escalation.event_id);
        let categories: std::collections::HashSet<_> =
            story.events.iter().map(|e| e.category).collect();
        assert!(categories.contains(&Category::Identity));
        assert!(categories.contains(&Category::Process));
        assert!(categories.contains(&Category::Privilege));
        assert_eq!(story.alerts.len(), 1);
    }

    #[tokio::test]
    async fn identity_story_by_uid_returns_that_users_events_and_citing_alerts() {
        let (_dir, storage) = test_storage();
        let root_event = session_event(
            EventType::PrivilegeUidChange,
            "3",
            0,
            Some("198.51.100.10"),
            1000,
        );
        let alice_event = session_event(
            EventType::PrivilegeUidChange,
            "3",
            1000,
            Some("198.51.100.10"),
            2000,
        );
        storage
            .batch_write(&[root_event.clone(), alice_event])
            .unwrap();
        storage
            .write_alerts(&[sample_alert("some_rule", vec![root_event.event_id], 1000)])
            .unwrap();

        let Json(story) = identity_story_handler(
            State(storage),
            Query(IdentityStoryQuery {
                session_id: None,
                uid: Some(0),
            }),
        )
        .await
        .unwrap();

        assert_eq!(story.events.len(), 1);
        assert_eq!(story.events[0].event_id, root_event.event_id);
        assert_eq!(story.alerts.len(), 1);
    }

    /// Global Constraint #10's disclosed asymmetry: the uid form does NOT
    /// fan out to every event of every session that user opened. The
    /// analyst who wants that starts from the session id, which every
    /// returned event carries.
    #[tokio::test]
    async fn identity_story_by_uid_does_not_expand_to_the_whole_session() {
        let (_dir, storage) = test_storage();
        // uid 0 logged in; a uid-1000 process then ran in that same session.
        let login_as_root = session_event(
            EventType::SessionLogin,
            "3",
            0,
            Some("198.51.100.10"),
            1000,
        );
        let alice_exec =
            session_event(EventType::ProcessExec, "3", 1000, Some("198.51.100.10"), 2000);
        storage
            .batch_write(&[login_as_root.clone(), alice_exec])
            .unwrap();

        let Json(story) = identity_story_handler(
            State(storage),
            Query(IdentityStoryQuery {
                session_id: None,
                uid: Some(0),
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            story.events.len(),
            1,
            "the uid form must not fan out into the session's other events"
        );
        assert_eq!(story.events[0].event_id, login_as_root.event_id);
        // ...and the session id is right there on it, so the analyst can
        // take the next step themselves.
        assert_eq!(
            story.events[0].session.as_ref().unwrap().session_id,
            "3"
        );
    }

    /// Both forms together intersect rather than union — the same
    /// composition rule every other filter pair in QueryPlan follows.
    #[tokio::test]
    async fn identity_story_with_both_params_intersects_them() {
        let (_dir, storage) = test_storage();
        let alice_in_3 = session_event(EventType::ProcessExec, "3", 1000, None, 1000);
        let root_in_3 = session_event(EventType::ProcessExec, "3", 0, None, 2000);
        let alice_in_4 = session_event(EventType::ProcessExec, "4", 1000, None, 3000);
        storage
            .batch_write(&[alice_in_3.clone(), root_in_3, alice_in_4])
            .unwrap();

        let Json(story) = identity_story_handler(
            State(storage),
            Query(IdentityStoryQuery {
                session_id: Some("3".to_string()),
                uid: Some(1000),
            }),
        )
        .await
        .unwrap();
        assert_eq!(story.events.len(), 1);
        assert_eq!(story.events[0].event_id, alice_in_3.event_id);
    }

    #[tokio::test]
    async fn identity_story_returns_an_empty_story_rather_than_404_for_an_unknown_session() {
        let (_dir, storage) = test_storage();
        let Json(story) = identity_story_handler(
            State(storage),
            Query(IdentityStoryQuery {
                session_id: Some("does-not-exist".to_string()),
                uid: None,
            }),
        )
        .await
        .unwrap();
        assert!(story.events.is_empty());
        assert!(story.alerts.is_empty());
    }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p osiris-api`
Expected: FAIL to compile — `cannot find function identity_story_handler`, `cannot find struct IdentityStoryQuery`.

- [ ] **Step 3: Implement the handler and register the route**

In `crates/osiris-api/src/lib.rs`, add the route to `build_router` immediately after the network line:

```rust
        .route("/api/v1/identity/story", get(identity_story_handler))
```

and append the handler after `network_story_handler`:

```rust
#[derive(Debug, Deserialize)]
struct IdentityStoryQuery {
    session_id: Option<String>,
    uid: Option<u32>,
}

#[derive(Debug, Serialize)]
struct IdentityStory {
    events: Vec<CanonicalEvent>,
    alerts: Vec<Alert>,
}

/// Composed query implementing Phase 4a plan Global Constraint #10, and
/// ARCHITECTURE.md §12.1's `*_story` shape — the same `{ events, alerts }`
/// response `FileStory` and `NetworkStory` already return, so one Console
/// renderer serves all three.
///
/// The two lookup forms are deliberately asymmetric:
///
/// * **`session_id`** returns every stored event carrying that session.
///   Because the Enrich stage attaches the session to every descendant of
///   the login (plan Global Constraint #5), that single filter returns the
///   genuinely multi-category chain §29's Phase 4 line calls for —
///   identity, process, privilege, file and network together — without any
///   graph walk. No Correlation Engine is involved; this is one indexed
///   column (plan Global Constraint #12).
/// * **`uid`** returns every stored event whose acting user is that uid. It
///   does NOT expand to "and everything in every session that user opened":
///   that second-pass fan-out is unbounded for a long-lived service
///   account, and §12.3's planner that could express it cheaply is Phase 7.
///   Every returned event carries its own session id, so the analyst who
///   wants the session view takes that one extra step deliberately.
///
/// Both may be given at once, in which case they intersect (they are two
/// `AND` clauses of one `QueryPlan`), which is what the single query below
/// gives for free.
async fn identity_story_handler(
    State(storage): State<Arc<dyn Storage>>,
    Query(q): Query<IdentityStoryQuery>,
) -> Result<Json<IdentityStory>, (StatusCode, String)> {
    if q.session_id.is_none() && q.uid.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "must provide session_id or uid".to_string(),
        ));
    }

    let (events, alerts) = tokio::task::spawn_blocking(move || {
        // Unlike the File and Network stories, this needs no union across
        // several queries: one indexed filter already selects the whole
        // chain, so there is no de-duplication step to perform and the
        // storage layer's own ORDER BY timestamp is the ordering.
        let mut plan = QueryPlan::new();
        plan.session_id = q.session_id.clone();
        plan.user_uid = q.uid;
        plan.limit = 10_000;
        let mut events = storage.query(&plan)?;
        // Storage already orders by timestamp; the secondary event_id key
        // makes the order total for same-timestamp events, matching the
        // File and Network stories exactly.
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

    Ok(Json(IdentityStory { events, alerts }))
}
```

- [ ] **Step 4: Run the API tests to verify they pass**

Run: `cargo test -p osiris-api`
Expected: PASS — every existing API test plus the six new ones.

Run: `cargo build --workspace --all-targets && cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-api
git commit -m "feat(api): GET /api/v1/identity/story

Query-param lookup by session_id or uid, returning the same
{ events, alerts } shape as the File and Network stories. The session form
is the multi-category one §29's Phase 4 line calls for: because Enrich
attaches the session to every descendant of a login, one indexed filter
returns identity, process, privilege, file and network events together —
no graph walk, no Correlation Engine.

The uid form deliberately does not fan out to every session that user
opened; every returned event carries its session id so an analyst can take
that step explicitly. GET /api/v1/users is not added — /api/v1/events?
event_type=SESSION_LOGIN already serves it.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01CQ6yt1YUcRLAqQad8DthQc"
```

---

### Task 8: `osiris-e2e-tests` — end-to-end verification of the identity/privilege vertical slice

**Files:**
- Modify: `crates/osiris-e2e-tests/tests/end_to_end.rs`

**Interfaces:**
- Consumes everything the previous seven tasks built, through the *real* components only: `Agent::start` with the real `AgentConfig`, the real spool file, the real `run_ingestion_loop`, the real `SqliteStorage`, the real `DetectionEngine::load_from_dir(config/rules)`, and the real `axum` router over real HTTP. No test double is substituted for any of them — that is the point of this task.
- Produces: one `#[tokio::test(flavor = "multi_thread")]` function, `ssh_sudo_escalation_flows_end_to_end_and_triggers_detection`, appended alongside Phase 1's, Phase 2's and Phase 3's. No existing e2e test is modified.

**Why this task exists and cannot be folded into the per-crate tests:** every task above proves its own crate in isolation. None of them proves that the session a *sensor* observed survives normalization, reaches the *storage* column, is *queryable*, and lets a *rule* fire — and Phase 3's retrospective recorded exactly this class of gap (a whole-branch review catching cross-file provenance mismatches that per-task review could not). Phase 3's Global Constraint #7/#8 checks are the model followed here: the entity-graph edges are asserted **directly on `event.relationships`**, not inferred from a Story endpoint's separate string-matching logic, because a Story join would pass even if the edges did not exist at all.

**Before writing any code**, read the existing `network_beacon_scenario_flows_end_to_end_and_triggers_detection` test top to bottom. This test follows its structure step for step (spawn Agent → open storage → load real rules → spawn ingestion loop → sleep → shut down → assert on storage → assert over HTTP → assert via the CLI binary), and reuses its `cli_binary_path()` helper unchanged. Note in particular the multi-thread runtime flavor and the reason for it recorded in Phase 1's test comment: the synchronous `std::process::Command::output()` call would starve a current-thread runtime's axum task.

- [ ] **Step 1: Write the failing end-to-end test**

Append to `crates/osiris-e2e-tests/tests/end_to_end.rs`:

```rust
/// Phase 4a's full vertical slice, and ARCHITECTURE.md §26's worked trace
/// from its true first step: sshd accepts a remote connection, audit
/// records the login, a shell runs inside that session, sudo escalates it
/// to root, and the escalated process writes root's authorized_keys and
/// calls out to a remote address — all through the real Agent (Sensor →
/// Pipeline → Bus → spool), the real Server (spool tailer → SqliteStorage →
/// DetectionEngine → alert persistence) and the real HTTP API.
///
/// Verifies, in order: every event landed; the session propagated from the
/// login down the whole process tree into the privilege, file and network
/// events (plan Global Constraint #5); both §9.4 entity edges are present
/// on exactly the right events and absent everywhere else (Global
/// Constraint #8), asserted on `event.relationships` directly rather than
/// inferred from the Story join; USER_REF_PARTIAL is applied only where
/// auditd genuinely cannot report gid/euid/egid (Global Constraint #6);
/// the shipped escalation rule fired and the other two did not; and the
/// Identity Story returns the full multi-category chain over real HTTP.
#[tokio::test(flavor = "multi_thread")]
async fn ssh_sudo_escalation_flows_end_to_end_and_triggers_detection() {
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
        enable_synthetic: true,
        synthetic_scenario: Some("ssh_sudo_escalation".to_string()),
        spool_path: spool_path.to_string_lossy().to_string(),
        status_addr: "127.0.0.1:0".to_string(),
    };
    let agent = Agent::start(agent_config, host, "e2e-boot".to_string())
        .await
        .unwrap();

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(&db_path).unwrap());

    // The real shipped rules directory — now three rules, loaded exactly
    // the way osiris-server's main.rs loads them.
    let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
    let detection_engine = Arc::new(DetectionEngine::load_from_dir(&rules_dir).unwrap());
    assert!(detection_engine.rule_count() >= 3);

    let ingestion_cancellation = CancellationToken::new();
    tokio::spawn(run_ingestion_loop(
        spool_path.clone(),
        storage.clone(),
        detection_engine,
        Duration::from_millis(50),
        ingestion_cancellation.clone(),
    ));

    // 9-event scenario, 1ms apart, plus a 50ms ingestion poll interval —
    // the same generous budget Phase 2 and Phase 3 used for comparable
    // scenario sizes.
    tokio::time::sleep(Duration::from_millis(1400)).await;
    agent.shutdown().await;
    ingestion_cancellation.cancel();

    // 1. Storage directly: all 9 events landed, across all five categories.
    let events = storage.query(&QueryPlan::new()).unwrap();
    assert_eq!(
        events.len(),
        9,
        "expected sshd/bash/sudo execs, login, sudo, uid change, file write, connect, logout"
    );

    // 2. Session propagation (Global Constraint #5): every event after the
    //    login carries the SSH session — including the file and network
    //    events, which is what makes the chain multi-category under one id.
    //    The sshd exec that preceded the login does NOT, and must not be
    //    retro-attributed.
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
        // Skip the pre-login exec checked above.
        if event.event_id == sshd_exec.event_id {
            continue;
        }
        let session = event
            .session
            .as_ref()
            .unwrap_or_else(|| panic!("{:?} must carry the session", event.event_type));
        assert_eq!(session.session_id, "3");
        assert_eq!(
            session.remote_addr.as_deref(),
            Some("198.51.100.10"),
            "{:?} must carry the login's remote address, not just its id",
            event.event_type
        );
        assert_eq!(session.auth_method.as_deref(), Some("sshd"));
    }

    // 3. The two §9.4 entity edges (Global Constraint #8), asserted on
    //    event.relationships directly — a Story join would pass even if
    //    these did not exist.
    let bash_exec = events
        .iter()
        .find(|e| {
            e.event_type == EventType::ProcessExec
                && e.process.as_ref().map(|p| p.pid) == Some(200)
        })
        .expect("the bash exec must be present");
    let triggered: Vec<_> = bash_exec
        .relationships
        .iter()
        .filter(|r| r.relation == Relation::TriggeredBySession)
        .collect();
    assert_eq!(
        triggered.len(),
        1,
        "a PROCESS_EXEC inside a session must carry exactly one TRIGGERED_BY_SESSION edge"
    );
    match (&triggered[0].from, &triggered[0].to) {
        (EntityRef::Process { process_key }, EntityRef::Session { session_id }) => {
            assert_eq!(*process_key, bash_exec.process.as_ref().unwrap().process_key);
            assert_eq!(session_id, "3");
        }
        other => panic!("TRIGGERED_BY_SESSION must be Process -> Session, got {:?}", other),
    }

    let escalation = events
        .iter()
        .find(|e| e.event_type == EventType::PrivilegeUidChange)
        .expect("the PRIVILEGE_UID_CHANGE event must be present");
    let executed_as: Vec<_> = escalation
        .relationships
        .iter()
        .filter(|r| r.relation == Relation::ExecutedAs)
        .collect();
    assert_eq!(
        executed_as.len(),
        1,
        "a real uid transition must carry exactly one EXECUTED_AS edge"
    );
    match &executed_as[0].to {
        EntityRef::User { uid, .. } => assert_eq!(*uid, 0, "the edge must target root"),
        other => panic!("EXECUTED_AS must target a User entity, got {:?}", other),
    }

    // ...and nowhere else. The sudo event names no target account (Global
    // Constraint #9), so it mints no EXECUTED_AS; the file and network
    // events carry the session but not a duplicate TRIGGERED_BY_SESSION.
    let sudo_event = events
        .iter()
        .find(|e| e.event_type == EventType::PrivilegeSudo)
        .expect("the PRIVILEGE_SUDO event must be present");
    assert!(
        sudo_event
            .relationships
            .iter()
            .all(|r| r.relation != Relation::ExecutedAs),
        "a USER_CMD-derived sudo event must not invent a target account"
    );
    for event in events.iter().filter(|e| {
        matches!(
            e.event_type,
            EventType::FileWrite | EventType::NetworkConnect | EventType::PrivilegeUidChange
        )
    }) {
        assert!(
            event
                .relationships
                .iter()
                .all(|r| r.relation != Relation::TriggeredBySession),
            "TRIGGERED_BY_SESSION belongs on PROCESS_EXEC only — repeating it on \
             every later event of a session writes one fact hundreds of times"
        );
    }

    // 4. Provenance tags (Global Constraints #4/#6): the sudo event is
    //    tagged partial because USER_CMD reports no gid/euid/egid; the
    //    SYSCALL-derived escalation is NOT, because it reports them for
    //    real. Both name the one Identity sensor in `provider`.
    assert!(
        sudo_event.tags.iter().any(|t| t == "USER_REF_PARTIAL"),
        "a USER_CMD-derived event must be tagged partial, not silently mirrored"
    );
    assert!(
        !escalation.tags.iter().any(|t| t == "USER_REF_PARTIAL"),
        "a SYSCALL-derived event reports gid/euid/egid for real and must not be tagged"
    );
    for event in [sudo_event, escalation] {
        assert!(
            event.provider.starts_with("identity_sensor/"),
            "§4.3 has no Privilege sensor row: privilege events name the Identity \
             sensor in `provider` (got {:?})",
            event.provider
        );
    }
    assert!(
        !events.iter().any(|e| e.tags.iter().any(|t| t == "INVALID")),
        "no event in this scenario may fail validation"
    );

    // 5. Storage's own new filters work on real ingested rows (Task 4).
    let mut plan = QueryPlan::new();
    plan.session_id = Some("3".to_string());
    assert_eq!(
        storage.query(&plan).unwrap().len(),
        8,
        "every event except the pre-login sshd exec belongs to session 3"
    );

    // 6. Over real HTTP: Timeline interleaving of all five categories.
    let app = build_router(storage.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let min_ts = events.iter().map(|e| e.timestamp).min().unwrap();
    let max_ts = events.iter().map(|e| e.timestamp).max().unwrap();
    let timeline: serde_json::Value = client
        .get(format!(
            "http://{}/api/v1/events?since={}&until={}",
            addr,
            min_ts - 1,
            max_ts + 1
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let timeline_events = timeline.as_array().unwrap();
    assert_eq!(timeline_events.len(), 9);
    let timestamps: Vec<u64> = timeline_events
        .iter()
        .map(|e| e["timestamp"].as_u64().unwrap())
        .collect();
    let mut sorted = timestamps.clone();
    sorted.sort();
    assert_eq!(timestamps, sorted, "events must come back in timestamp order");
    let categories: std::collections::HashSet<_> = timeline_events
        .iter()
        .map(|e| e["category"].as_str().unwrap().to_string())
        .collect();
    for expected in ["IDENTITY", "PROCESS", "PRIVILEGE", "FILE", "NETWORK"] {
        assert!(
            categories.contains(expected),
            "§29's Phase 4 line requires a genuinely multi-category chain; missing {expected}"
        );
    }

    // 7. The shipped escalation rule fired — and only it. The file write
    //    is to /root/.ssh, not /var/www, and the connection is to a bare IP
    //    with no DNS query, so Phase 2's and Phase 3's rules must stay
    //    silent on this scenario.
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
        1,
        "exactly one alert: the escalation rule, not the web-root or DNS rules"
    );
    assert_eq!(
        alerts_array[0]["rule_id"].as_str().unwrap(),
        "privilege_escalation_to_root_in_remote_session"
    );
    let reasons = alerts_array[0]["reasons"].as_array().unwrap();
    assert_eq!(reasons.len(), 3);
    assert!(reasons.iter().all(|r| !r.as_str().unwrap().trim().is_empty()));
    // §11.1: the alert cites the exact rule revision that fired.
    assert_eq!(
        alerts_array[0]["rule_content_hash"].as_str().unwrap().len(),
        64
    );
    // ...and it cites the escalation event as its evidence.
    let evidence: Vec<&str> = alerts_array[0]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(evidence.contains(&escalation.event_id.to_string().as_str()));

    // 8. Identity Story by session over real HTTP: the whole
    //    identity->process->privilege->file->network chain plus the citing
    //    alert, in one response (Global Constraint #10's session form).
    let story: serde_json::Value = client
        .get(format!("http://{}/api/v1/identity/story?session_id=3", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let story_events = story["events"].as_array().unwrap();
    assert_eq!(
        story_events.len(),
        8,
        "the session story must contain every event of the session"
    );
    let story_categories: std::collections::HashSet<_> = story_events
        .iter()
        .map(|e| e["category"].as_str().unwrap().to_string())
        .collect();
    for expected in ["IDENTITY", "PROCESS", "PRIVILEGE", "FILE", "NETWORK"] {
        assert!(story_categories.contains(expected), "story missing {expected}");
    }
    assert_eq!(story["alerts"].as_array().unwrap().len(), 1);

    // 9. Identity Story by uid: Global Constraint #10's disclosed
    //    asymmetry — the uid form does not fan out to the whole session.
    //    uid 0 acted on the login, the logout and the outbound connection
    //    (which the escalated process made as root); it did not act on the
    //    uid-1000 events.
    let uid_story: serde_json::Value = client
        .get(format!("http://{}/api/v1/identity/story?uid=0", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let uid_story_events = uid_story["events"].as_array().unwrap();
    assert!(
        uid_story_events.len() < story_events.len(),
        "the uid form must NOT expand to every event in the sessions that user opened \
         — Global Constraint #10's disclosed asymmetry"
    );
    assert!(uid_story_events
        .iter()
        .all(|e| e["user"]["uid"].as_u64() == Some(0)));

    // 10. The real CLI binary still works against this richer dataset
    //     (regression check, unchanged from Phase 2/3).
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

Two things to verify against the real code rather than trusting the snippet: the `AgentConfig` literal must list **every** field the struct has at this point (Task 5 added `identity_audit_log_path`; the compiler will name any other omission), and the alert JSON field names (`rule_id`, `reasons`, `rule_content_hash`, `evidence`) must match `Alert`'s actual serde names in `crates/osiris-schema/` — Phase 3's e2e test already reads `rule_id` and `reasons`, so follow it for those two and check the other two before asserting on them. If `Alert` serializes the content hash under a different name, use that name; do not drop the assertion.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p osiris-e2e-tests ssh_sudo_escalation`
Expected: FAIL — before Tasks 3-7 are complete this does not compile; once they are, run it and confirm it passes on the first honest run rather than after loosening an assertion. A failing count assertion here is a real finding about session propagation, not a number to adjust.

- [ ] **Step 3: Run the whole workspace**

Run: `cargo build -p osiris-cli` first (the CLI-binary regression check in step 10 requires the binary to exist in the same target directory — the same prerequisite Phase 1's test documented), then:

Run: `cargo test --workspace`
Expected: PASS — every test in every crate, including all four e2e scenarios (Phase 1's exec chain, Phase 2's web-shell drop, Phase 3's network beacon, Phase 4a's SSH/sudo escalation) and the perf smoke test.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS.

Run: `cargo fmt --all -- --check`
Expected: PASS.

Run: `bash tools/check-dep-graph.sh`
Expected: `Dependency-graph check PASSED`.

- [ ] **Step 4: Commit**

```bash
git add crates/osiris-e2e-tests
git commit -m "test(e2e): prove the Phase 4a identity/privilege vertical slice end-to-end

The ssh_sudo_escalation scenario through the real Agent, Server and HTTP
API: nine events across IDENTITY, PROCESS, PRIVILEGE, FILE and NETWORK,
every one after the login carrying the SSH session's id, remote address and
auth method — which is ARCHITECTURE.md §26's worked trace reproducible from
its first step, and §29's Phase 4 requirement that the chain become
genuinely multi-category.

Asserts the two §9.4 edges directly on event.relationships (a Story join
would pass without them): TRIGGERED_BY_SESSION on the exec only,
EXECUTED_AS on the real uid transition only, and neither on the sudo event
whose target account auditd does not report. Asserts USER_REF_PARTIAL
appears exactly where the backend genuinely cannot report gid/euid/egid,
that the escalation rule fires alone, and that the Identity Story returns
the whole chain over real HTTP.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01CQ6yt1YUcRLAqQad8DthQc"
```

---

## Self-Review

**Spec coverage.** Every Global Constraint above is implemented by a specific, named task, and none is left as prose only:

| # | Constraint | Where it lands |
|---|---|---|
| 1 | Phase 4a scope split | The plan's title/Goal, plus the "Deferred to Phase 4b" section below |
| 2 | Audit-log backend only | Task 3's `IdentitySensor` (no utmp/wtmp/loginuid code anywhere in its Files list) and its doc comment |
| 3 | Exactly seven `EventType`s | Task 1's two operation enums, Task 2's two `match` blocks, Task 3's `parse_record` (with an explicit test that syscalls 113/114 are ignored) |
| 4 | One sensor emits both families | Task 3's single `LineTailer` + `IdentityRecord` enum, its `emits_both_…_from_one_tailed_log` test, and Task 2's `identity_provider` naming both families `identity_sensor/audit` |
| 5 | Best-effort session, never faked | Task 2's `SessionResolver` and its six tests; Task 8's assertion that the pre-login exec is *not* retro-attributed |
| 6 | `USER_REF_PARTIAL` | Task 2's `build_user_ref`; Task 8 asserts it appears on the sudo event and not on the SYSCALL-derived one |
| 7 | Zero `osiris-schema` changes | No task's Files list contains `crates/osiris-schema/`; Task 1's pre-flight re-verifies the enum/struct list against live source. Re-confirmed while writing this continuation: `Category::{Identity,Privilege}`, all four `Session*` and five `Privilege*` `EventType` variants with their `category()` mapping, `UserRef{uid,gid,euid,egid,username,loginuid}`, `SessionRef{session_id,tty,remote_addr,auth_method}`, `EntityRef::{User{host_id,uid},Session{session_id}}` and `Relation::{ExecutedAs,TriggeredBySession}` all exist today at `cdc722e` |
| 8 | Exactly two edges, precise attachment | Task 2's `attach_session_relationship`/`attach_executed_as_relationship` plus four negative tests; Task 8 re-asserts on real ingested rows |
| 9 | auditd format confidence boundary | Task 3's `split_record` (the `msg=` collision), `unknown_to_none` (the `?` mapping), `sudo`'s `target_uid: None`, and the `a0=ffffffff` test |
| 10 | Story route shape and asymmetry | Task 7's route, handler doc comment and the two asymmetry tests; Task 8 step 9 over HTTP |
| 11 | Two columns, two filters, guarded migration | Task 4, including the pre-Phase-4 migration test |
| 12 | No Correlation Engine | No task creates a chain type, graph walker, or per-entity state table; Task 7's handler is one indexed query and says so |
| 13 | No `osiris-detect` source changes | Task 6's pre-flight verifies the four `eval.rs`/`engine.rs` behaviours against live source, and its Step 5 makes the "tests only" claim checkable with `git diff` |
| 14 | No `osiris-server`/`osiris-cli` changes | Neither path appears in any task's Files list; Task 8 exercises `run_ingestion_loop` and the CLI binary unchanged |
| 15 | One dep-graph line | Task 3 Step 2, run for real in Step 12 |

**Constraint #13 verified, not assumed.** Reading `crates/osiris-detect/src/eval.rs` and `engine.rs` at `cdc722e` confirms all four behaviours Task 6 depends on: `field_value` walks a dotted path with `current.get(segment)?`; it returns `None` on an explicit JSON `null` (`if current.is_null() { return None; }`); `evaluate_rule`'s `let actual = field_value(event_json, &condition.field)?;` propagates that `None` out of the whole rule; and `load_from_dir` globs and sorts `*.yaml`/`*.yml` with no registration step. The `Operator` enum is exactly `{Eq, Ne, Contains, StartsWith, EndsWith, In}` — there is genuinely no existence operator, which is why the rule's remote-address condition is `ne ""` and why that idiom needed the null-is-absent behaviour to be true. **Task 6 therefore requires no `osiris-detect` source change, and that claim is checked against the real files, not inferred from this plan's own prose.**

**ARCHITECTURE.md conformance.** §2.1's layering holds: the new sensor crate depends only on `osiris-sensor-api` and `osiris-fileutil` (both below it), and Task 3's dep-graph line makes the Server/API direction enforceable. §4.2's sensor-independence rule holds: `osiris-sensors-identity` depends on no sibling sensor — which is exactly why Task 3 duplicates `decode_untrusted_string`/`decode_hex` rather than importing them from `osiris-sensors-fs`, a duplication that is a deliberate architectural cost and is documented as such at the function. §7.1's stage order is preserved (`attach_session` runs inside Enrich, between process resolution and edge attachment). §7.2's Agent/Server enrichment split is preserved by not doing server-side enrichment at all. §9.2's envelope is populated, never extended. §11.3's Correlation Engine is not built. §12.1's `*_story` shape is matched exactly. §18/§27's privilege boundary gains one new enforced edge and relaxes none.

**Frozen-schema check.** Zero changes to `crates/osiris-schema/`. The one place a frozen type genuinely did not fit — `UserRef`'s non-optional `gid`/`euid`/`egid` against auditd's `USER_*` records, which report only `uid` — is solved in the consuming crate with a mirror-plus-tag, matching Phase 2's standing precedent (solve it above the schema or defer; never widen). The one place the frozen `Relation` enum genuinely has no variant — "this session belongs to this user" — is left unrepresented as an edge rather than overloading `SPAWNED` or `EXECUTED_AS`, with the fact carried losslessly by the event's own `user`/`session` fields. Both decisions are recorded at their call sites, not only here.

**Type consistency.** `IdentityEventRaw`/`PrivilegeEventRaw` (Task 1) are constructed in three independent places — Task 2's normalize tests, Task 3's `audit_record.rs`, Task 5's generator scenario — and consumed in one (Task 2's `normalize_identity_event`/`normalize_privilege_event`). Every field name and type was cross-checked across all four while writing this continuation; in particular the `ppid: 0` "no parent reported" convention is used identically by Task 3's `sudo()`, Task 5's scenario and Task 2's `SessionResolver::attach` early return, and `session_id` is `String` on the identity struct but `Option<String>` on the privilege struct in all four places. `QueryPlan.session_id`/`.user_uid` (Task 4) are consumed with matching names in Task 7's handler and Task 8's storage assertion. `IdentityStory`'s `{ events, alerts }` matches `FileStory`/`NetworkStory` exactly. The rule file's `event_data.target_uid` and `session.remote_addr` field paths (Task 6) match the JSON names Task 2 actually produces (`event_data` is built with a `"target_uid"` key; `session` serializes `SessionRef`'s `remote_addr`), not assumed OQL-style names.

**Build/test commands.** Every `cargo test -p <crate>` names a crate that exists in the workspace (`osiris-sensor-api`, `osiris-pipeline`, `osiris-sensors-identity` after Task 3 Step 2, `osiris-storage`, `osiris-storage-sqlite`, `osiris-generator`, `osiris-agent`, `osiris-detect`, `osiris-api`, `osiris-e2e-tests`) — note the generator's package name is `osiris-generator` even though its directory is `generator/`, which is why the `-p` flags say so. `bash tools/check-dep-graph.sh` is the real script path. Task 8 Step 3 requires `cargo build -p osiris-cli` before the workspace test run, matching the prerequisite Phase 1's e2e test documented for `cli_binary_path()`. Phase 2's retrospective lesson is honoured: Tasks 3, 5, 7 and 8 each run `cargo build --workspace --all-targets` or `cargo test --workspace`, not only their own `-p`-scoped command.

**Placeholder scan.** No task contains "TBD", "add appropriate error handling", or an unshown "similar to Task N" — every step that changes code shows the code. The largest single unit is Task 3 (13 steps, one new crate with a parser and a sensor); it was kept whole rather than split because the splitter, the parser and the sensor share one contract that only makes sense tested together, matching Phase 2's Task 4 and Phase 3's Task 3 precedent.

**Residual risks, flagged rather than hidden.**

1. **`SessionResolver`'s unbounded `by_pid` map.** Bounded only by logout (Global Constraint #5). A long-lived session spawning very many short-lived processes accumulates one entry per pid until it ends, and a session that never cleanly logs out never prunes. This is disclosed in the resolver's own doc comment and is genuinely unfixable here: there is no `PROCESS_EXIT` event type emitted by any sensor in this codebase. It should be the *first* item a Phase 4b/5 planning session reconsiders if a process-exit sensor lands.
2. **ppid-inheritance is a heuristic, not the kernel's own session attribution.** Real `PROCESS_EXEC` audit records carry `ses=` directly, but Phase 1's `ProcessExecRaw` does not, and widening it would ripple through the Phase 1 parser, generator, pipeline and every existing test. The heuristic is correct for the normal exec-tree case and fails closed (`None`) otherwise, but a process re-parented to init after its session leader dies would keep the session it inherited rather than losing it. Adding `ses` to `ProcessExecRaw` is the honest long-term fix and is a self-contained follow-up.
3. **The `ne ""` idiom for "field is present".** Task 6's rule reads correctly only because `field_value` maps null to `None`. That behaviour is tested inside `osiris-detect` today, so a regression would be caught there — but the coupling is implicit, not expressed in the rule language. If Phase 6's rule compiler adds a real `exists` operator, this rule should be migrated to it.
4. **Timing-based e2e assertions.** Task 8 sleeps 1400ms for a 9-event scenario at a 50ms ingestion interval. That is the same generous ratio Phase 2 and Phase 3 used and both have been stable, but it is wall-clock-dependent and could flake on a heavily loaded CI machine. If it does, raise the sleep — never lower the expected event count.
5. **Real-auditd validation is still deferred.** Every fixture in Task 3 is written from documented auditd behaviour, held to the same bar as Phase 1/2/3, but no line in this plan has been checked against a live `auditd` on a real Linux host, because the development environment has none. The `USER_CMD` target-account and capability-bitmask fields were excluded precisely because that check could not be made (Global Constraint #9); the fields that *are* parsed are the ones documented consistently enough to rely on. First contact with a real host remains the phase's largest unretired risk, unchanged from Phase 2.

**Corrections made during this pass.** Two, both caught by reading live source rather than this plan's prose. First, the `USER_CMD` fixture originally omitted `exe=`; real sudo builds usually include it, so the fixture now carries it and a separate test covers the build that omits it — with `exe_path` left empty rather than hard-coded to `/usr/bin/sudo`. Second, an early draft of the Identity Story handler unioned two separate queries (one per lookup form) the way `network_story_handler` does; reading Task 4's `QueryPlan` made clear that two `AND` clauses of a single plan give intersection for free and need no de-duplication pass, so the handler is one query and its doc comment says why it differs from its two siblings.

---

## Deferred to Phase 4b

Global Constraint #1 promised this section so the next planning session does not have to re-derive the split. ARCHITECTURE.md §29's Phase 4 line names five deliverables; this plan ships the first three (Identity Sensor, Privilege telemetry, SSH/sudo correlation). The remaining two are **Phase 4b**, and they belong together for the same reason the first three did: they share a shape with each other and share nothing structural with this plan.

**Systemd Sensor** (§4.3's Systemd row). Backend: subprocess output from `systemctl list-units --type=service --all --no-pager --no-legend` and `systemctl list-timers --all --no-pager --no-legend`, polled on an interval and diffed against the previous snapshot to derive unit start/stop/enable/mask transitions — the same poll-and-diff shape `osiris-sensors-net`'s `NetworkPoller` already established for `/proc/net/tcp`, and portably testable here against fixture text captured from those commands' documented output formats. `sd-bus`/D-Bus subscription (§4.3's primary backend, and the `Source::Dbus` variant the frozen enum already has) is the eventual real backend and is a second `Sensor` implementation behind the same trait, not a rewrite. Emits the `SERVICE_*` family from §9.3's taxonomy and populates `CanonicalEvent.service`, which — like `session`/`user` before this phase — no code has ever populated.

**Persistence Monitor** (§4.3's Persistence row). Backend: filesystem scanning of the paths Linux persistence techniques actually use — `/etc/cron.d/`, `/etc/crontab`, `/var/spool/cron/crontabs/`, systemd unit directories (`/etc/systemd/system/`, `/usr/lib/systemd/system/`, `~/.config/systemd/user/`), `/etc/rc.local`, `/etc/init.d/`, `/etc/ld.so.preload`, `~/.bashrc`-family shell profiles, and `~/.ssh/authorized_keys` — snapshotted and diffed, so an added or modified persistence artifact becomes an event rather than requiring an analyst to notice a file write among thousands. Emits the `PERSIST_*` family. Note the deliberate overlap with Phase 2's Filesystem sensor: a write to `/etc/cron.d/x` produces both a `FILE_WRITE` (what happened to the file) and a `PERSIST_*` event (what it means), and Phase 4b must decide explicitly whether those are two events or one — this plan takes no position.

**Why they are not in this plan.** Different backends (subprocess output and directory scanning; neither tails an audit log), different `EventType` families (`SERVICE_*`/`PERSIST_*`; no overlap with the seven here), a different Story shape if either gets one, and zero dependency on anything Phase 4a builds beyond the Sensor→Pipeline→Storage→API pattern every phase since Phase 1 has re-used. §26's worked trace — the thing §29's Phase 4 line points at as the goal — contains no systemd unit and no persistence path, so it is fully reproducible after this plan alone. Phase 4b is additive telemetry, not the completion of a half-built mechanism.

**What Phase 4b inherits from here.** The pipeline pattern (a new `RawEvent` variant, a `normalize_*` function, a `PriorityTable` entry, a `validate` clause), the guarded additive storage migration (Task 4's loop takes new columns the same way), the dep-graph line per new sensor crate (Task 3 Step 2), and the `Source` enum's existing `Dbus` variant. It inherits no unfinished work and no known defect from this plan — only the five residual risks listed in the Self-Review above, of which items 1 and 2 (`SessionResolver` pruning and ppid inheritance) are the two a Phase 4b or Phase 5 planner should re-examine first.
