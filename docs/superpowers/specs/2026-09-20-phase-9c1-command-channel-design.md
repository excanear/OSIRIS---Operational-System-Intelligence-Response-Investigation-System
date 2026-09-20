# Phase 9c-1 — Server→Agent command channel + TerminateProcess / QuarantineFile

Status: design approved in chat 2026-09-20. Part 1 of 9c (ARCHITECTURE.md §13, §29;
docs/ROADMAP-REMAINING.md). 9c-2 (StopService, BlockIndicator, IsolateNetwork,
DisablePersistence) and 9d (fleet manager) are separate phases.

## 1. Goal and non-goals

Goal: let the Server make an enrolled Agent perform a destructive response action, with the
privilege boundary of §13 intact (the Server never touches host processes/files; only the Agent does,
and only for authenticated, signed, fresh commands addressed to it). Activate exactly two actions:

* `TerminateProcess` — irreversible, so guarded hardest.
* `QuarantineFile` — reversible (moved into an Agent-owned vault), plus a `RestoreFile` command.

Non-goals: the other four destructive actions (they keep answering 501), policy distribution,
command queueing for offline agents, two-person approval, real-Linux validation (Phase 10; the
Linux-only code here is validated by compilation and a fake executor).

## 2. Architecture

New crate `osiris-command` (protocol + crypto + executor trait; no I/O policy of its own):

* `envelope` — `Command`, `SignedCommand`, `CommandResult`, canonical byte encoding, Ed25519
  sign/verify.
* `guard` — the Agent-side verifier: signature, addressee, expiry, replay window, protected targets.
* `executor` — `trait ActionExecutor` (`terminate`, `quarantine`, `restore`, each with a `dry_run`
  flavour) and `FakeExecutor` for tests. The real `LinuxExecutor` lives in `osiris-agent`
  (`cfg(target_os = "linux")`, a stub that returns `Unsupported` elsewhere).

`osiris-transport` gains a **control connection**, separate from the event connection:

* The Agent dials the Server (outbound only, works behind NAT), mTLS with the same enrolled
  certificate, on a dedicated control listener (`control_listen_addr`, distinct port from the event
  listener). The Server binds the connection to the host id in the certificate (same
  `HOST_URI_PREFIX` rule as events).
* Wire messages (`wire.rs`, new enums so the event protocol is untouched):
  `ControlServerMsg::{Command(SignedCommand), Ping}` and
  `ControlClientMsg::{Hello{agent_version}, Result(CommandResult), Pong}`.
* Server side: `ControlHub` keeps `host_id -> sender` for connected agents. One connection per host;
  a newer connection replaces the older one. `ControlHub::send(host_id, cmd, timeout)` returns
  `AgentOffline` immediately when no connection exists (no queueing, so a stale command can never run
  later), otherwise waits for the matching `CommandResult` up to the timeout.
* Same hardening as 9a/9b: handshake timeout, global and per-IP connection caps, idle timeout with
  ping/pong, tight frame limits, graceful shutdown on the server cancellation token.

`osiris-response` / `osiris-api` integration:

* `dispatch()` stays synchronous and pure for `CollectEvidence` and the server-side preview.
* A new async trait `CommandDispatcher` (`async fn dispatch(host_id, SignedCommand, timeout) ->
  Result<CommandResult, DispatchError>`) is injected into `ResponseState`; production impl wraps
  `ControlHub`, tests use a fake.
* `ResponseOutcome` gains `Executed{..}`, `ExecutionFailed{..}`, `TimedOut`, `AgentOffline`.
  `Rejected` (→ 501) remains for the four non-activated actions.
* The audit bracket is unchanged in shape: pre-execution write fails closed (500, nothing is sent);
  post-execution write records the real Agent result, best-effort with a warn on failure.

## 3. Command envelope and trust

* Server holds an Ed25519 **command-signing key**, separate from TLS keys, created by
  `osiris pki init-command-key` (private key `0600`, public key file). The Agent config pins the public
  key (`command_public_key`). No pinned key ⇒ the control connection is not started and the Agent
  logs it at startup (fail closed).
* `Command` fields: `command_id` (UUID), `host_id` (addressee), `action`
  (`TerminateProcess{process_key}` | `QuarantineFile{file_id, path_hint}` |
  `RestoreFile{quarantine_id}`), `dry_run`, `issued_at`, `expires_at`, `nonce`,
  `actor` and `reason` (for the Agent's local log; the authoritative audit is on the Server).
  Canonical encoding = fixed-order length-prefixed fields, not JSON, so the signed bytes are
  unambiguous.
* TTL default 30 s, hard maximum 120 s (Agent refuses a longer `expires_at - issued_at`). Agent
  tolerates ±60 s clock skew on `issued_at` and otherwise judges by its own clock against
  `expires_at`.
* Replay: the Agent persists seen `command_id`s (with expiry) in `command_seen.log` next to its
  spool, fsynced before execution starts; ids are dropped after `expires_at + skew`. A repeat is
  refused with `Replay` (and is idempotently reported, never re-executed).
* The Agent rejects, before doing anything: bad signature, wrong `host_id`, expired, TTL too long,
  replayed, unknown action. Each rejection is a typed `CommandResult::Refused{reason}`.

## 4. Agent-side execution

* Commands run one at a time (a single executor task fed by a bounded channel, capacity 8; more
  in flight ⇒ `Refused{Busy}`), each under the command timeout.
* **Protected targets (built in, not configurable):** pid 1, the Agent's own pid and ancestors, the
  Server pid when co-located, kernel threads (`ppid == 2` / no exe), and anything under the
  quarantine vault. Refused with `Refused{ProtectedTarget}` — checked again inside the executor,
  not only in the guard.
* `TerminateProcess`: resolve `process_key` (host boot id + pid + start time) against `/proc`; if the
  pid now belongs to a different start time (pid reuse) ⇒ `Failed{TargetChanged}` and nothing is
  signalled. SIGTERM, wait up to 5 s, then SIGKILL, re-verifying identity before each signal.
  Result reports which signal ended it.
* `QuarantineFile`: open by path, verify `(inode, device_id)` equals the requested `file_id`
  (else `Failed{TargetChanged}`), hash it (sha256), move it (rename, or copy+fsync+unlink across
  filesystems) into `<vault>/<quarantine_id>` with mode `0000`, and write a sidecar
  `<quarantine_id>.json` (original path, mode, uid/gid, hash, time). Vault dir is `0700`, owned by
  the Agent user. Result carries `quarantine_id` and hash.
* `RestoreFile{quarantine_id}`: verify the vault hash still matches, recreate at the original path
  with the original mode/owner, refuse if the path exists (`Failed{DestinationExists}`).
* **Dry-run** is real: the Agent runs the full guard, resolves the target and returns
  `DryRunOk{would_do}` or the refusal/failure it *would* have produced, without any side effect.

## 5. Server-side flow (`POST /api/v1/response/{action}`)

Unchanged up to authorization: RBAC `ResponseOperator`, mandatory reason, tenant scoping, target
resolution against stored events (unknown target ⇒ 400/404 as today). Then for the two active
actions:

1. Resolve the host: `TerminateProcess` from the process key's host, `QuarantineFile` from the
   file entity's `host_id`. A tenant user may only address hosts in its tenant (else 404).
2. Pre-execution audit write (fail closed).
3. Build, sign and send the command through `CommandDispatcher` with the timeout.
4. Map the result to an HTTP response: `Executed` 200, `ExecutionFailed` 200 with `ok=false` and the
   failure code, `TimedOut` 504, `AgentOffline` 409, `Refused` 422, unknown/transport error 502.
5. Post-execution audit write with the real outcome. `QuarantineFile` also records the
   `quarantine_id` so an operator can request `POST /api/v1/response/restore_file`
   (same gate, same audit).
6. Dry-run: sends a `dry_run` command when the agent is online (result flagged
   `agent_validated: true`); when offline it returns today's server-side preview flagged
   `agent_validated: false` rather than failing.

RBAC table: `restore_file` joins the response prefix rule (`ResponseOperator`). No per-action
carve-outs.

## 6. Configuration and CLI

* Server: `control` section (`listen_addr`, `command_signing_key`, `max_connections`,
  `max_connections_per_ip`, `command_timeout_secs` default 30). Absent ⇒ control listener off and the
  two actions answer 409 `AgentOffline`-style "control channel disabled" (never 501, never silent).
* Agent: `control` section (`server_addr`, `command_public_key`, `vault_dir`). Reuses the transport
  client certificate paths.
* CLI: `osiris pki init-command-key`, `osiris response terminate-process|quarantine-file|restore-file`
  thin wrappers of the API (dry-run flag supported).
* Docs: `docs/operators-response-actions.md` (setup, key handling, what each action does, protected
  targets, restore procedure, the irreversibility of terminate).

## 7. Security requirements (for the dedicated review)

* Compromised Console session or API token cannot forge a command: signing key is server-only and
  never reachable from API handlers beyond the dispatcher.
* Compromised network path cannot forge, alter, or replay a command; cannot address another host.
* A stolen agent certificate cannot make the agent execute anything (the agent only *receives*
  commands, and only signed ones) and cannot receive another host's commands (bound by cert host id).
* No TOCTOU on identity: pid-reuse and inode-swap checks happen at action time in the executor.
* Failure paths never act: any verification error ⇒ refusal, never a best-effort execution.
* Tenancy: commands and results are host-scoped; tenant checks happen before signing.

## 8. Testing

* `osiris-command` unit tests: canonical encoding stability (golden bytes), sign/verify, each guard
  rejection (bad sig, wrong host, expired, TTL too long, skewed issue time, replay incl. across
  restart, unknown action, protected targets), executor contract via `FakeExecutor`.
* Transport tests over real mTLS: control connection binds to cert host id; hub replace-on-reconnect;
  offline ⇒ immediate `AgentOffline`; timeout ⇒ `TimedOut`; caps/timeouts like 9a/9b.
* Linux executor tests behind `cfg(target_os = "linux")`, using real child processes and temp dirs
  (pid reuse simulated by start-time mismatch); not runnable on the Windows dev host, so they must at
  least compile via `cargo clippy --workspace --all-targets` on the CI Linux runner.
* API tests (composed router, real `auth_gate`): 401/403/tenant-404, reason required, pre-audit
  failure ⇒ 500 with nothing sent, every outcome ⇒ correct status and two audit entries, dry-run with
  agent online/offline.
* End-to-end (`osiris-e2e-tests`): server + fake-executor agent over the real control channel:
  terminate, quarantine, restore, refused replay.

## 9. Known limitations to record

* Linux-only execution is unvalidated on real kernels until Phase 10.
* One executor task per agent serialises commands.
* Clock skew tolerance is fixed (±60 s).
* No offline queueing by design; an operator retries.
* `TerminateProcess` has no rollback.

## 10. Amendment (2026-09-20, found while writing the plan)

`ProcessKey` is a one-way hash, and real sensor events carry no `/proc`-comparable start time, so
the Agent cannot resolve a process from the key. §3/§4 are amended: `TerminateProcess` carries
`{pid, exe_path, observed_at_ns}` taken by the Server from the stored event that resolved the
target. The Agent requires `/proc/<pid>/exe == exe_path` **and** the process start time
`<= observed_at_ns + 2 s`; otherwise `Failed{TargetChanged}` (or `Unverifiable` if `/proc` cannot be
read). `QuarantineFile` carries `{path, inode, device_id}`. See the plan header for the exact rule.
