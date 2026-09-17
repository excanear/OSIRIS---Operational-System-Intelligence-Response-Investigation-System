# Phase 8b — Response Engine (v1 scaffolding) — Design

**Status:** approved (autonomous execution per standing user instruction — see project memory `feedback-osiris-workflow`)
**Parent:** Phase 8 — Kubernetes/Cloud/Multi-host (`ARCHITECTURE.md` §29/§93), decomposed into 8a–8e (decomposition first made explicit in [[phase-8a-rbac-auth-foundation-design]]). This is 8b: the Response Engine, built directly on 8a's RBAC/Auth (`Role::ResponseOperator`, `AuthContext`, `auth_gate`) rather than inventing a second authorization mechanism.
**Pre-agreed context:** `ARCHITECTURE.md` §13 (Response Engine Architecture — the authoritative v1 scope boundary for this phase), §22 (Audit System, `osiris-audit`, already implemented), §12.6 (Evidence, `osiris-evidence`, already implemented), §14.2 (`POST /api/v1/response/{action}` named in the endpoint table but never built).

## 1. Scope

§13 draws an explicit v1 boundary: implement the **audit/authorization/dry-run scaffolding fully**, for every declared `ResponseAction`, and implement **evidence collection (non-destructive) for real**; process/service/network **destructive** actions (`TerminateProcess`, `StopService`, `QuarantineFile`, `BlockIndicator`, `IsolateNetwork`, `DisablePersistence`) are architected — types exist, the authz path exists, the audit path exists — but do not actually dispatch, because the Agent↔Server command channel §13 requires ("the API/Core never executes a response action directly on the host — it dispatches a signed command to the relevant host's Agent") does not exist yet (§8.3 only carries events upward today). Building that bidirectional channel is explicitly out of scope for this phase — it belongs to the separately-versioned "Response — Active Actions" milestone §13 itself names.

This phase therefore ships: the `ResponseAction` type system, the full `AuthCheck → Confirmation → Audit(pre) → Dispatch → Result → Audit(post)` pipeline from §13, working end-to-end for `CollectEvidence`, and a well-defined, fully-audited **rejection** path for every destructive action (never a silent no-op — §17.3's "No destructive Response action executes without the full authz+audit path" and §95's "no destructive response silently" both apply to the *rejection* itself, not just to a hypothetical successful execution).

## 2. Architecture

New crate `osiris-response`, following this project's established one-crate-per-subsystem pattern (mirrors `osiris-auth`, `osiris-evidence`) — pure domain logic, no HTTP/axum dependency, testable standalone.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResponseActionKind {
    TerminateProcess,
    StopService,
    QuarantineFile,
    BlockIndicator,
    IsolateNetwork,
    DisablePersistence,
    CollectEvidence,
}

impl ResponseActionKind {
    /// All variants except `CollectEvidence`.
    pub fn destructive(&self) -> bool;
    /// `true` for every variant in v1 — dry-run is the one mode every
    /// action can honor today, destructive or not.
    pub fn supports_dry_run(&self) -> bool;
}

pub struct ResponseRequest {
    pub action: ResponseActionKind,
    pub target: EntityRef,       // osiris_schema::EntityRef — reused, not reinvented
    pub reason: String,          // required, validated non-empty before dispatch() is called
    pub dry_run: bool,
    pub since: Option<u64>,      // CollectEvidence only
    pub until: Option<u64>,      // CollectEvidence only
    pub incident_id: Option<Uuid>, // CollectEvidence only, optional link
}

pub enum ResponseOutcome {
    DryRunPreview { description: String },
    EvidenceCollected { evidence_id: Uuid },
    Rejected { reason: String },  // destructive + non-dry-run in v1
}

pub fn dispatch(
    request: &ResponseRequest,
    storage: &dyn Storage,
    evidence_store: &dyn EvidenceStore,
    links: &dyn EvidenceIncidentLinks,   // only consulted if incident_id is Some
) -> Result<ResponseOutcome, ResponseError>;
```

`dispatch()` does **not** touch the audit log — audit writing is the caller's (the `osiris-api` handler's) responsibility, exactly like every other audited mutation in this codebase (`create_user_handler`, the incident/evidence handlers) already does via `AuthState.audit_log`. This keeps `osiris-response` free of an `AuditLog` dependency and keeps the two audit writes (pre and post) visibly bracketing the `dispatch()` call in the handler, matching §13's "pre-execution … Dispatch … post-execution" ordering literally in the code, not just in prose.

Three branches inside `dispatch()`:

1. **`dry_run: true`** (any action): validates the target resolves to something real in `storage` (e.g. a `Process` `EntityRef` whose `process_key` has at least one stored event; a `File`/`Ip`/`Domain`/`Container`/`User` `EntityRef` likewise) and returns `DryRunPreview` with a human-readable description of what the action *would* do (e.g. `"would terminate process <process_key> (pid <pid>, host <host_id>) — no signal sent, dry run"`). No mutation, no dispatch attempt, no Agent involvement even in concept.
2. **`dry_run: false`, `CollectEvidence`**: queries events touching `target` within `[since.unwrap_or(0), until.unwrap_or(u64::MAX)]`, reusing the same entity-scoped, time-bounded query pattern the `*_story` handlers already use against `Storage` (no new query primitive). Serializes the matched event set, computes a `sha256` hash as `Integrity{hash, immutable_since: now}`, constructs `Evidence::new(EvidenceSource::EventCapture, now, integrity, vec![target.clone()], supersedes: None)`, inserts it via `EvidenceStore`, and — if `incident_id` was given — links it via `EvidenceIncidentLinks::link`. Returns `EvidenceCollected { evidence_id }`. Zero events matching is not an error (an empty evidence bundle is still evidence of absence) — validated by a dedicated test.
3. **`dry_run: false`, destructive**: returns `Rejected { reason: "Active Actions milestone not yet shipped — see ARCHITECTURE.md §13/§29" }` without touching `storage`/`evidence_store` at all. This is a deliberate, typed outcome — not a `Result::Err` — because it is not a failure of the pipeline (authz and confirmation both succeeded); it is a correct, expected v1 answer that the caller must still audit as `AuditResult::Failure` (§13's own "Result recorded (including failure)" line — a rejection is a kind of failure to actually act, and gets the same two-phase audit treatment as any other execution failure would, not skipped).

## 3. API (`osiris-api`)

New `POST /api/v1/response/{action}` handler in a new `response.rs` module (mirrors the existing `incidents.rs`/`evidence.rs` handler-module split, not a new merge-router — this single route is added to the same router `build_incident_evidence_router` (or a sibling small router merged the same way) assembles, following `main.rs`'s existing composition pattern from 8a).

`min_role_for` (already `(Method, path) -> Role` since 8a's Fix 2) gets one more entry: any method on `/api/v1/response/` (prefix match, trailing slash — same load-bearing pattern 8a's fix used for `/incidents/`) → `Role::ResponseOperator`. This applies uniformly to dry-run and real requests, and to `CollectEvidence` as well as the destructive kinds — one endpoint, one required role, no per-action carve-out, which keeps the RBAC table's invariant ("evaluable independent of any handler logic," §14.3) intact.

Request body:
```json
{
  "target": "<EntityRef, using EntityRef::parse_storage_key's KIND:value form>",
  "reason": "non-empty string",
  "dry_run": true,
  "since": 0,
  "until": 18446744073709551615,
  "incident_id": null
}
```
`since`/`until`/`incident_id` are accepted but ignored for non-`CollectEvidence` actions (no error — a client sending them harmlessly is simpler than rejecting extra fields, matching this API's existing permissive-body convention elsewhere).

Handler flow:
1. Parse `{action}` path segment into `ResponseActionKind` (unknown → `404`, matching how an unknown route already 404s post-gate).
2. Parse body; `reason.trim().is_empty()` → `400`, **no audit entry written** (nothing was meaningfully requested — matches `create_user_handler`'s existing pattern of validating before any store/audit write).
3. Parse `target` via `EntityRef::parse_storage_key` → `400` on failure, no audit entry (same reasoning as 2).
4. Write the **pre-execution** audit entry: `who: ActorRef::User{user_id}` (from `AuthContext`), `what: "response.<action>.dry_run" | "response.<action>.execute"`, `target: target.clone()`, `why: Some(reason.clone())`, `result: AuditResult::Success` (recording that the *request* was accepted and is proceeding — not yet its outcome).
5. Call `osiris_response::dispatch(...)` inside `tokio::task::spawn_blocking` (matches every other `Storage`-touching handler's existing blocking-call convention).
6. Write the **post-execution** audit entry based on the outcome:
   - `DryRunPreview` → `result: Success`, `why: Some(description)` — recording what the preview said, for a reviewable trail of what an operator was shown before ever escalating to a real request.
   - `EvidenceCollected` → `result: Success`, `target` stays the **original request's target** (`EntityRef` has no "evidence record" variant today — `Process`/`File`/`Ip`/`Domain`/`User`/`Container` only, per `osiris-schema::relationships`, and this phase does not add one just for an audit-trail convenience, matching this codebase's existing "schema-frozen" precedent), `why` is extended to include the new `evidence_id` (e.g. `"<reason> (evidence_id=<uuid>)"`) so the trail still names it.
   - `Rejected` → `result: Failure`, `why: Some(rejected_reason)`.
   - `dispatch()` returning `Err(ResponseError)` (a genuine internal failure — storage I/O error, etc.) → `result: Failure`, `why: Some(err.to_string())`, HTTP `500`.
7. HTTP response:
   - dry-run → `200 { "dry_run": true, "preview": "<description>" }`
   - CollectEvidence real → `200 { "dry_run": false, "evidence_id": "<uuid>" }`
   - destructive real (`Rejected`) → `501 { "error": "not_implemented", "message": "<rejected_reason>" }`
   - internal error → `500 { "error": "internal", "message": "<...>" }`

## 4. Error handling

| Condition | HTTP | Audit entries written |
|---|---|---|
| Missing/invalid token | 401 | none (auth_gate rejects before the handler runs) |
| Valid token, role < ResponseOperator | 403 | none (same) |
| Empty `reason` | 400 | none |
| Unparseable `target` | 400 | none |
| Unknown `{action}` | 404 | none |
| Valid dry-run request | 200 | 1 (pre only — dry-run's pre-entry *is* its record; there is no separate "result" to distinguish, so a second identical entry would be pure duplication) |
| Valid CollectEvidence execute | 200 | 2 (pre + post) |
| Valid destructive execute | 501 | 2 (pre + post, post is `Failure`) |
| `dispatch()` internal error | 500 | 2 (pre + post, post is `Failure`) |

Dry-run intentionally writes exactly **one** audit entry, not two — re-reading §13's "pre-execution … Dispatch … Result … post-execution" sequence, the two-phase design exists specifically to survive a crash *during* dispatch (so a record of intent still exists if the result never gets recorded). A dry-run has no dispatch step to crash during — `dispatch()` returns synchronously with the preview already in hand — so a second entry would only assert "yes, the preview above is what happened," which the single entry's `why` field already states. This asymmetry is called out here explicitly so it reads as a decision, not an inconsistency, when the implementation plan/tests reference it.

## 5. Testing

- `osiris-response`: unit tests for `dispatch()` directly against a temp-dir-backed `SqliteStorage`/`SqliteEvidenceStore`/`SqliteEvidenceIncidentLinks` (no HTTP) — one test per branch (dry-run preview for a destructive action, dry-run preview for CollectEvidence, CollectEvidence with events present, CollectEvidence with zero matching events, CollectEvidence with an `incident_id` link, every destructive kind's `Rejected` outcome, an invalid/unresolvable `target` in dry-run mode).
- `osiris-api`: integration tests for the handler — RBAC (Viewer/Analyst 403, ResponseOperator 200/501), the 400s (empty reason, bad target), the 404 (unknown action), and — critically — **audit-entry-count assertions** reading the real `FileAuditLog` back (1 for dry-run, 2 for execute), since that count is this design's main correctness invariant and nothing else in the codebase currently asserts on audit-log shape this precisely.
- No Console/CLI work in this phase's must-ship scope (see Non-Goals) — no RTL/CLI tests needed.

## 6. Non-Goals (explicitly deferred)

- **Actual dispatch of any destructive action** — the entire point of this phase's scope boundary (§1 above). Belongs to the "Response — Active Actions" milestone, which also needs the Agent↔Server command channel (signed commands, §13) that doesn't exist yet.
- **Console UI for Response actions** — no screen, no button. §16.3's screen table doesn't name one yet, and building an "execute a response action" UI ahead of the API actually being able to execute anything destructive would front-run the Active Actions milestone's own security review (§13's explicit reason for gating it separately). CollectEvidence *could* get a Console affordance later (e.g. from Process Explorer/Entity Graph), but that's additive UI on an already-shipped API — not required to consider this phase done, matching the established backend-then-Console-as-fast-follow pattern.
- **CLI command for `osiris-cli response ...`** — same reasoning; a fast-follow, not required for this phase.
- **A response-history/status list endpoint** (`GET /api/v1/response` or similar) — `GET /api/v1/audit` (built in 8a) already gives an Admin-readable trail of every response request via its `what`/`target`/`result` fields; a dedicated response-specific view is additive polish, not required to make the engine's audit guarantee real.
- **Per-action RBAC granularity** (e.g. `CollectEvidence` at `Analyst`, destructive at `ResponseOperator`) — deliberately deferred per §3 above; revisit only if a real need for finer-grained roles emerges.
