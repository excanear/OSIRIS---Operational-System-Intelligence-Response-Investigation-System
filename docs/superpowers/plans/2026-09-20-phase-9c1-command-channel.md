# Phase 9c-1 Command Channel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the Server make an enrolled Agent execute `TerminateProcess` / `QuarantineFile` (+ `RestoreFile`) through signed commands over a dedicated mTLS control connection, with audit, timeouts and dry-run.

**Architecture:** New crate `osiris-command` (envelope, Ed25519 signing, agent-side guard, replay store, `ActionExecutor` trait, pure runner). `osiris-transport` gains a control connection (Agent dials Server; Server-side `ControlHub` routes commands by certificate host id). `osiris-response`/`osiris-api` gain an async `CommandDispatcher` and new outcomes; the Agent gets a `LinuxExecutor` (cfg linux) behind the trait.

**Tech Stack:** Rust workspace, tokio, rustls (existing transport), `ed25519-dalek` 2 (new), axum (existing API), `libc` (new, Linux-only target dep).

**Spec:** `docs/superpowers/specs/2026-09-20-phase-9c1-command-channel-design.md` (read it first).

## Spec amendment (supersedes spec §3/§4 where they differ)

`ProcessKey` is a one-way hash of (host, boot_id, pid, start_time_mono), and real sensor events do not carry a `/proc`-comparable start time. So the command cannot carry the key and the Agent cannot re-derive it. Instead:

* `TerminateProcess { pid: u32, exe_path: String, observed_at_ns: u64 }`, filled by the Server from the stored event that resolved the target (`process.pid`, `process.exe_path`, event `timestamp`, which is nanoseconds since the Unix epoch).
* Agent identity check (pid-reuse defence): `/proc/<pid>/exe` must equal `exe_path` **and** the process's start time (boot time + `starttime`/`CLK_TCK`, in ns) must be `<= observed_at_ns + 2 s`. A process started after the observation is a different process: `Failed{TargetChanged}`. Anything unreadable ⇒ `Failed{Unverifiable}`. Nothing is signalled unless both checks pass, and they are re-run before SIGKILL.
* `QuarantineFile { path: String, inode: u64, device_id: u64 }` (`device_id` in OSIRIS encoding `(major<<32)|minor`).
* The pure part of the check is `process_started_by(start_ns, observed_at_ns)` in `osiris-command` so it is testable on the Windows dev host.

## Global Constraints

* Timestamps in commands are milliseconds since Unix epoch (`issued_at_ms`, `expires_at_ms`). Event timestamps are nanoseconds.
* Command TTL default 30 s, hard max 120 s; issue-time skew tolerance ±60 s.
* Control connections: handshake timeout 5 s, idle timeout 300 s with 30 s ping, ≤1024 connections, ≤16 per IP, frame limits as in `osiris-transport::frame`.
* Protected targets are built in and not configurable: pid 1, the Agent's own pid and its ancestors, the quarantine vault, kernel threads (Linux executor).
* Every verification failure refuses; nothing ever "best-effort executes".
* Before any commit: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (rebuild `osiris-cli osiris-server osiris-agent` first: `cargo build -p osiris-cli -p osiris-server -p osiris-agent`).
* Commit messages end with `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.
* Model for subagents: `sonnet` (haiku is org-blocked on this account).
* Windows dev host: Linux-only code lives under `#[cfg(target_os = "linux")]` with a non-Linux stub; it must still pass `cargo clippy` here (stub) and be written to compile on Linux.

---

### Task 1: `osiris-command` crate — envelope, canonical bytes, Ed25519

**Files:**
- Create: `crates/osiris-command/Cargo.toml`, `crates/osiris-command/src/lib.rs`, `crates/osiris-command/src/envelope.rs`, `crates/osiris-command/src/keys.rs`
- Modify: `Cargo.toml` (workspace members + `ed25519-dalek = { version = "2", features = ["rand_core"] }`)

**Interfaces:**
- Produces (all `pub`, used by later tasks):
  - `enum CommandAction { TerminateProcess{pid:u32, exe_path:String, observed_at_ns:u64}, QuarantineFile{path:String, inode:u64, device_id:u64}, RestoreFile{quarantine_id:Uuid} }` (serde, `Clone, Debug, PartialEq, Eq`)
  - `struct Command { command_id:Uuid, host_id:Uuid, action:CommandAction, dry_run:bool, issued_at_ms:u64, expires_at_ms:u64, nonce:[u8;16], actor:String, reason:String }` with `fn canonical_bytes(&self)->Vec<u8>`
  - `struct SignedCommand { command:Command, signature:Vec<u8> }`
  - `fn sign(cmd:Command, key:&SigningKey)->SignedCommand`, `fn verify(sc:&SignedCommand, key:&VerifyingKey)->Result<(), CommandError>`
  - `enum CommandError { BadSignature, Io(String), BadKey(String) }`
  - keys: `fn generate_signing_key()->SigningKey`, `fn write_signing_key(dir:&Path, name:&str)->Result<(), CommandError>` (writes `<name>.key` mode 0600 unix, `<name>.pub`, both hex, refuses to overwrite), `fn load_signing_key(path:&Path)`, `fn load_verifying_key(path:&Path)`.
  - re-export `ed25519_dalek::{SigningKey, VerifyingKey}`.

- [ ] **Step 1: Failing tests** in `envelope.rs` `#[cfg(test)]`:

```rust
fn sample(action: CommandAction) -> Command {
    Command {
        command_id: Uuid::from_u128(1), host_id: Uuid::from_u128(2), action,
        dry_run: false, issued_at_ms: 1_000, expires_at_ms: 31_000,
        nonce: [7u8; 16], actor: "alice".into(), reason: "malware".into(),
    }
}
fn term() -> CommandAction {
    CommandAction::TerminateProcess { pid: 42, exe_path: "/bin/x".into(), observed_at_ns: 5 }
}
#[test] fn canonical_bytes_start_with_domain_tag_and_are_stable() {
    let b = sample(term()).canonical_bytes();
    assert!(b.starts_with(b"osiris-cmd-v1\0"));
    assert_eq!(b, sample(term()).canonical_bytes());
}
#[test] fn changing_any_field_changes_the_bytes() {
    let base = sample(term()).canonical_bytes();
    let mut c = sample(term()); c.host_id = Uuid::from_u128(3); assert_ne!(base, c.canonical_bytes());
    let mut c = sample(term()); c.dry_run = true; assert_ne!(base, c.canonical_bytes());
    let mut c = sample(term()); c.expires_at_ms += 1; assert_ne!(base, c.canonical_bytes());
    let mut c = sample(term()); c.nonce[0] = 0; assert_ne!(base, c.canonical_bytes());
    let mut c = sample(term()); c.reason = "other".into(); assert_ne!(base, c.canonical_bytes());
    let other = CommandAction::TerminateProcess { pid: 43, exe_path: "/bin/x".into(), observed_at_ns: 5 };
    assert_ne!(base, sample(other).canonical_bytes());
}
#[test] fn field_boundaries_are_unambiguous() {
    // ("ab","c") must differ from ("a","bc"): length prefixes, not concatenation.
    let mut a = sample(term()); a.actor = "ab".into(); a.reason = "c".into();
    let mut b = sample(term()); b.actor = "a".into();  b.reason = "bc".into();
    assert_ne!(a.canonical_bytes(), b.canonical_bytes());
}
#[test] fn sign_then_verify_roundtrips_and_tamper_fails() {
    let key = crate::keys::generate_signing_key();
    let sc = sign(sample(term()), &key);
    assert!(verify(&sc, &key.verifying_key()).is_ok());
    let mut bad = sc.clone(); bad.command.host_id = Uuid::from_u128(9);
    assert!(matches!(verify(&bad, &key.verifying_key()), Err(CommandError::BadSignature)));
    let other = crate::keys::generate_signing_key();
    assert!(matches!(verify(&sc, &other.verifying_key()), Err(CommandError::BadSignature)));
    let mut short = sc.clone(); short.signature.truncate(10);
    assert!(matches!(verify(&short, &key.verifying_key()), Err(CommandError::BadSignature)));
}
```
and in `keys.rs`: `write_signing_key` then `load_signing_key`/`load_verifying_key` roundtrip and a second `write_signing_key` on the same dir/name errors (tempfile dir).

- [ ] **Step 2: Run** `cargo test -p osiris-command` → fails (crate missing/unimplemented).
- [ ] **Step 3: Implement.** Canonical encoding: `b"osiris-cmd-v1\0"`, `command_id` 16 bytes, `host_id` 16 bytes, `dry_run` 1 byte, `issued_at_ms` u64 BE, `expires_at_ms` u64 BE, `nonce` 16 bytes, action tag byte (`1` terminate, `2` quarantine, `3` restore) followed by its fields (u32 BE for pid; strings as u32-BE-length + UTF-8; u64 BE numbers; uuid 16 bytes), then `actor` and `reason` as length-prefixed strings. `sign` = `SigningKey::sign(canonical_bytes)`; `verify` parses the 64-byte signature (`Signature::from_slice`; wrong length ⇒ `BadSignature`) and uses `verify_strict`. Key files are lowercase hex of the 32 raw bytes; refuse overwrite with `OpenOptions::create_new(true)`, mode 0600 on unix via `OpenOptionsExt`.
- [ ] **Step 4: Run** `cargo test -p osiris-command` → all pass.
- [ ] **Step 5: Commit** `feat(command): signed command envelope and Ed25519 keys`.

---

### Task 2: Guard, replay store, runner, `ActionExecutor`

**Files:**
- Create: `crates/osiris-command/src/guard.rs`, `replay.rs`, `executor.rs`, `runner.rs`, `identity.rs`
- Modify: `crates/osiris-command/src/lib.rs` (declare + re-export), `Cargo.toml` (`tempfile` dev-dep)

**Interfaces:**
- Consumes: Task 1 types.
- Produces:
  - `enum Refusal { BadSignature, WrongHost, Expired, NotYetValid, TtlTooLong, Replay, Busy, ProtectedTarget(String) }` (`Display`, serde)
  - `enum FailCode { TargetChanged, Unverifiable, NotFound, DestinationExists, Io, Unsupported }`
  - `enum CommandResult { Refused{reason:Refusal}, DryRunOk{would_do:String}, Executed{detail:ExecDetail}, Failed{code:FailCode, message:String} }` (serde, `Clone, Debug, PartialEq`)
  - `struct ExecDetail { summary:String, quarantine_id:Option<Uuid>, sha256:Option<String>, signal:Option<String> }`
  - `trait ActionExecutor: Send + Sync { fn terminate(&self,pid:u32,exe_path:&str,observed_at_ns:u64,dry_run:bool)->Result<ExecDetail,ExecFailure>; fn quarantine(&self,path:&str,inode:u64,device_id:u64,dry_run:bool)->Result<ExecDetail,ExecFailure>; fn restore(&self,id:Uuid,dry_run:bool)->Result<ExecDetail,ExecFailure>; }` and `struct ExecFailure{code:FailCode,message:String}`; `struct FakeExecutor` (records calls in a `Mutex<Vec<String>>`, configurable `fail_with: Option<FailCode>`).
  - `struct ProtectedTargets { pub agent_pid:u32, pub extra_pids:Vec<u32>, pub vault:PathBuf }` with `check_pid(&self,pid)->Result<(),Refusal>` (pid 1, agent pid, extra pids) and `check_path(&self,path)->Result<(),Refusal>` (under the vault).
  - `struct ReplayStore` with `open(path:&Path)->io::Result<Self>` and `check_and_record(&self,id:Uuid,expires_at_ms:u64,now_ms:u64)->Result<(),Refusal>` (fsync append **before** returning `Ok`; prunes entries older than `expires_at + 60_000`; reloads from file on `open`).
  - `struct Guard { host_id, key:VerifyingKey, replay:ReplayStore, protected:ProtectedTargets }` with `fn admit(&self, sc:&SignedCommand, now_ms:u64)->Result<(), Refusal>` (order: signature, host, ttl `expires-issued <= 120_000`, `issued_at_ms <= now+60_000`, `now < expires_at_ms`, replay, protected targets for the action).
  - `fn run_command(guard:&Guard, exec:&dyn ActionExecutor, sc:&SignedCommand, now_ms:u64)->CommandResult` — `admit` first; a refusal never reaches the executor; then dispatch by action honoring `dry_run` (`DryRunOk{would_do}` from the executor's `Ok` summary when `dry_run`).
  - `fn process_started_by(start_ns:u64, observed_at_ns:u64)->bool` = `start_ns <= observed_at_ns + 2_000_000_000` (identity.rs).

- [ ] **Step 1: Failing tests.** In `guard.rs` build a `Guard` with a temp replay file and helper `signed(action, |c| mutate)`; one test per refusal: bad signature, wrong host, `expires-issued=121_000` ⇒ `TtlTooLong`, `issued_at_ms = now+61_000` ⇒ `NotYetValid`, `now >= expires` ⇒ `Expired`, same command twice ⇒ second is `Replay`, replay survives `ReplayStore::open` on the same file (simulated restart), pid 1 / agent pid ⇒ `ProtectedTarget`, path inside vault ⇒ `ProtectedTarget`, and a fully valid command ⇒ `Ok`. In `runner.rs`: a refused command leaves `FakeExecutor` calls empty; a valid terminate calls the fake once; `dry_run=true` returns `DryRunOk` and the fake records it as a dry run; `fail_with=TargetChanged` ⇒ `Failed{TargetChanged,..}`. In `identity.rs`: `process_started_by(100, 100)`, `(1_000_000_000, 0)` true (within 2 s), `(3_000_000_000, 0)` false.
- [ ] **Step 2: Run** `cargo test -p osiris-command` → fails.
- [ ] **Step 3: Implement** as specified. `ReplayStore` file format: one line per id `"<uuid> <expires_at_ms>\n"`, kept in a `Mutex<HashMap<Uuid,u64>>`; `check_and_record` returns `Replay` if present and not pruned, else appends + `sync_data()` then inserts.
- [ ] **Step 4: Run** tests → pass; `cargo clippy -p osiris-command --all-targets -- -D warnings`.
- [ ] **Step 5: Commit** `feat(command): guard, replay store, runner and executor trait`.

---

### Task 3: Transport control connection (`ControlHub`, listener, client)

**Files:**
- Create: `crates/osiris-transport/src/control.rs`
- Modify: `crates/osiris-transport/src/wire.rs`, `lib.rs`, `Cargo.toml` (`osiris-command = { path = "../osiris-command" }`)

**Interfaces:**
- Consumes: `SignedCommand`, `CommandResult`; existing `tls::{server_config, client_config}`, `frame::{read_frame, write_frame}`, `server::{host_id_from_cert, IpCounter-like caps (copy the small pattern; do not export server internals)}`.
- Produces:
  - wire: `enum ControlServerMsg { Command(SignedCommand), Ping }`, `enum ControlClientMsg { Hello{agent_version:String}, Result{command_id:Uuid, result:CommandResult}, Pong }`
  - `struct ControlHub` (`Clone`, cheap) with `fn new()->Self`, `fn connected(&self, host:Uuid)->bool`, `async fn send(&self, host:Uuid, cmd:SignedCommand, timeout:Duration)->Result<CommandResult, SendError>`; `enum SendError { Offline, TimedOut, Disconnected }`
  - `struct ControlListener` with `bind(addr,&str, tls:Arc<rustls::ServerConfig>, revoked:HashSet<Uuid>, hub:ControlHub)->io::Result<Self>`, `local_addr()`, `run(self, cancel:CancellationToken)`
  - `trait CommandHandler: Send + Sync { async fn handle(&self, cmd:SignedCommand)->CommandResult; }` (`async_trait`)
  - `struct ControlClientConfig { server_addr, server_name, ca, cert, key: (same types as ForwarderConfig) }` and `async fn run_control_client(cfg:ControlClientConfig, handler:Arc<dyn CommandHandler>, cancel:CancellationToken)->Result<(),TlsError>` (reconnect with the same `Backoff` policy as the forwarder: 1 s doubling to 30 s, reset after a `Hello` was written).

- [ ] **Step 1: Failing tests** in `control.rs` (real mTLS with `pki` helpers, mirror the setup used by the existing tests in `server.rs`/`client.rs` — read them first and reuse their fixture style): (a) an agent connects, `hub.connected(host)` becomes true, `hub.send` reaches a `CommandHandler` fake and returns its result; (b) `send` to a host with no connection returns `Offline` immediately; (c) handler that sleeps longer than the timeout ⇒ `TimedOut`, and a later result for that command is ignored; (d) a second connection for the same host replaces the first and the old pending sends get `Disconnected`; (e) a revoked host is refused; (f) 17th connection from one IP is refused; (g) cancelling the token closes the listener.
- [ ] **Step 2: Run** `cargo test -p osiris-transport control` → fail.
- [ ] **Step 3: Implement.** Hub state: `Arc<Mutex<HashMap<Uuid, HostConn>>>` with `HostConn { tx: mpsc::Sender<(SignedCommand, oneshot::Sender<CommandResult>)>, id: u64 }`. Per-connection task selects on: outbound commands (writes `Command`, stores `oneshot` in a `HashMap<Uuid,…>` keyed by `command_id`), inbound frames (`Result` completes the matching oneshot; `Pong` resets idle), a 30 s ping ticker, and cancel. On exit, remove from the hub only if `id` still matches (replace-on-reconnect) and drop all pending oneshots (⇒ `Disconnected`). Reuse the 9a hardening constants. `send` = lookup ⇒ `Offline`; else send + `tokio::time::timeout`.
- [ ] **Step 4: Run** tests → pass; clippy.
- [ ] **Step 5: Commit** `feat(transport): server-to-agent control connection with ControlHub`.

---

### Task 4: Agent — config, `LinuxExecutor`, control task

**Files:**
- Create: `crates/osiris-agent/src/control.rs`, `crates/osiris-agent/src/linux_exec.rs`
- Modify: `crates/osiris-agent/src/config.rs` (`ControlConfig`), `agent.rs` (spawn task), `lib.rs`, `Cargo.toml` (`osiris-command`, `[target.'cfg(target_os="linux")'.dependencies] libc = "0.2"`)

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces:
  - `struct ControlConfig { server_addr:String, server_name:String, ca:String, cert:String, key:String, command_public_key:String, vault_dir:String }` (`#[serde(default)] pub control: Option<ControlConfig>` on `AgentConfig`; absent ⇒ no control connection).
  - `struct AgentCommandHandler` implementing `CommandHandler`: holds `Guard`, `Arc<dyn ActionExecutor>`, a bounded semaphore of 1 executing + queue depth 8 (more ⇒ `Refused{Busy}`), runs `run_command` on `spawn_blocking` under a 30 s timeout (timeout ⇒ `Failed{Io,"timed out"}`).
  - `LinuxExecutor { vault: PathBuf }` implementing `ActionExecutor` (Linux) / `UnsupportedExecutor` returning `Failed{Unsupported}` elsewhere; `fn default_executor(vault)->Arc<dyn ActionExecutor>` chooses by `cfg`.

- [ ] **Step 1: Failing tests** (portable ones use `FakeExecutor`): `AgentCommandHandler` with a fake executor returns `Refused{Replay}` for a repeated command and `Refused{Busy}` when 9 commands are pushed while the fake blocks; config parses `control:` and a config without it still loads (`control == None`). Linux-only tests (`#[cfg(all(test, target_os="linux"))]`) in `linux_exec.rs`: spawn a `sleep 60` child and terminate it (`observed_at_ns` = now, `exe_path` = the child's exe) ⇒ process gone; wrong `exe_path` ⇒ `TargetChanged` and child alive; `observed_at_ns = 0` for a just-started child ⇒ `TargetChanged`; quarantine a temp file (moved into `vault`, mode 0000, sidecar JSON written, original path gone, sha256 recorded), restore recreates it with original mode, restore when destination exists ⇒ `DestinationExists`, inode swapped ⇒ `TargetChanged`, path under vault ⇒ refused by guard.
- [ ] **Step 2: Run** `cargo test -p osiris-agent` → fail.
- [ ] **Step 3: Implement.** `LinuxExecutor::terminate`: read `/proc/<pid>/exe` (`std::fs::read_link`), compare to `exe_path`; parse `/proc/<pid>/stat` field 22 (`starttime` ticks, skip past the last `)` to be robust to spaces in comm), `btime` from `/proc/stat`, `CLK_TCK` via `libc::sysconf(_SC_CLK_TCK)`; start_ns = `(btime + starttime/clk)` in ns; reject with `TargetChanged` unless `process_started_by`; refuse kernel threads (empty `exe` link / `ppid==2`); `dry_run` returns the summary without signalling; else `libc::kill(pid, SIGTERM)`, poll up to 5 s for exit (`/proc/<pid>` gone or start time changed), then re-verify identity and `SIGKILL`. `quarantine`: `File::open`, `fstat` compare `(st_ino, encode(major(st_dev),minor(st_dev)))`, sha256 by streaming, `rename` into `vault/<uuid>` (fallback copy+`sync_all`+unlink on `EXDEV`), chmod 0000, write `<uuid>.json` (`path, mode, uid, gid, sha256, quarantined_at`); vault created 0700. `restore`: read sidecar, verify hash of the vaulted file, refuse if destination exists, rename back, restore mode/owner (`libc::chown`). Wire in `agent.rs` next to the forwarder task: build `Guard` (verifying key from `command_public_key`, replay file `<spool>.command_seen`, `ProtectedTargets{agent_pid: std::process::id(), extra_pids: ancestors_of(agent_pid), vault}`), then `run_control_client`. Missing/unreadable public key ⇒ log an error and do not start the control task (fail closed).
- [ ] **Step 4: Run** `cargo test -p osiris-agent`, `cargo clippy -p osiris-agent --all-targets -- -D warnings` (Linux-only tests are compiled out on this host; write them carefully and note it in the report).
- [ ] **Step 5: Commit** `feat(agent): control connection, guard wiring and Linux executor`.

---

### Task 5: Server — control listener, key, `CommandDispatcher`, CLI key command

**Files:**
- Create: `crates/osiris-server/src/control.rs`
- Modify: `crates/osiris-server/src/config.rs` (`ControlServerConfig`), `main.rs`, `lib.rs`, `Cargo.toml`; `crates/osiris-cli/src/main.rs` (`pki init-command-key`)
- Modify: `crates/osiris-response/src/lib.rs` + `Cargo.toml` for the trait (see Task 6 — define the trait here in `osiris-response`, so Task 6 consumes it)

**Interfaces:**
- Produces in `osiris-response`: `#[async_trait] pub trait CommandDispatcher: Send + Sync { async fn dispatch(&self, host_id: Uuid, action: CommandAction, dry_run: bool, actor: String, reason: String) -> Result<CommandResult, DispatchError>; }` and `enum DispatchError { Disabled, Offline, TimedOut, Failed(String) }`.
- Produces in `osiris-server`: `struct HubDispatcher { hub:ControlHub, key:SigningKey, timeout:Duration }` implementing it (builds `Command` with fresh `command_id`, random `nonce`, `issued_at_ms = now`, `expires_at_ms = now + timeout + 5_000` capped at 120_000, signs, `hub.send`). `struct DisabledDispatcher` returning `Disabled`.
- Config: `control: Option<ControlServerConfig { listen_addr, cert, key, client_ca, command_signing_key, revoked_hosts (default []), max_connections (default 1024), max_connections_per_ip (default 16), command_timeout_secs (default 30) }`.
- CLI: `osiris pki init-command-key --dir <d> [--name command]` writes `<name>.key` (0600) and `<name>.pub` via `osiris_command::keys::write_signing_key` (refuse overwrite; print the `.pub` path and the agent config line to use).

- [ ] **Step 1: Failing tests:** dispatcher builds a command that `verify`s with the public key and is addressed to the right host, TTL ≤ 120 s, fresh nonce/id each call; `Offline` mapped from `SendError::Offline`; config with and without `control` parses; validation rejects `command_timeout_secs` of 0 or > 110; CLI test `init_command_key_writes_a_key_pair_and_refuses_overwrite`.
- [ ] **Step 2: Run** the new tests → fail.
- [ ] **Step 3: Implement** and wire in `main.rs` next to the agent listener: if `control` is set, load TLS (`tls::server_config`), signing key (`load_signing_key`, refuse to start on failure, exit 1 like `agent_listener`), bind `ControlListener`, spawn `run(cancel)`, and build `HubDispatcher`; else `DisabledDispatcher`. Pass the `Arc<dyn CommandDispatcher>` into `ResponseState` (Task 6 adds the field; keep the workspace compiling by adding the field in this task with a default in test helpers). Log INFO whether the control channel is enabled.
- [ ] **Step 4: Run** tests; clippy; build the three binaries.
- [ ] **Step 5: Commit** `feat(server): control listener, command signing and HubDispatcher`.

---

### Task 6: Response engine + API integration

**Files:**
- Modify: `crates/osiris-response/src/lib.rs`, `dispatch.rs`; `crates/osiris-api/src/response.rs`, `auth_middleware.rs` (`restore_file` under the response prefix rule), `lib.rs` exports; `crates/osiris-api/tests/composed_router_auth.rs`, `composed_router_tenancy.rs`

**Interfaces:**
- Consumes: `CommandDispatcher`, `DispatchError` (Task 5), `CommandAction`, `CommandResult`.
- Produces: `ResponseActionKind::RestoreFile` (wire `RESTORE_FILE`, `destructive() = true`); `ResponseOutcome` gains `Executed{ detail:String, quarantine_id:Option<Uuid> }`, `ExecutionFailed{ code:String, message:String }`, `Refused{ reason:String }`, `TimedOut`, `AgentOffline`, `ControlDisabled`. `pub fn remote_action(request:&ResponseRequest, sample:&CanonicalEvent)->Result<(Uuid, CommandAction), ResponseError>` in `osiris-response` mapping `TerminateProcess`+`EntityRef::Process` to `(sample.host_id, TerminateProcess{pid, exe_path, observed_at_ns: sample.timestamp})` and `QuarantineFile`+`EntityRef::File` to `(host_id, QuarantineFile{path, inode, device_id})` using the most recent matching event that has `process`/`file` populated (`ResponseError::UnknownTarget` otherwise). `ResponseState` gains `pub commands: Arc<dyn CommandDispatcher>`.
- Request body for restore: target is `EntityRef::Domain`-free; add optional `quarantine_id` + `host_id` fields to the request body (`RestoreFile` only; required for it, rejected for others ⇒ 422). Read `response.rs`'s body struct first and follow its serde style.

- [ ] **Step 1: Failing tests** in `response.rs` (fake `CommandDispatcher` recording calls; follow the existing test harness in that file): terminate with agent result `Executed` ⇒ 200 + two audit entries with the real result; `Offline` ⇒ 409, `TimedOut` ⇒ 504, `Refused` ⇒ 422, `Disabled` ⇒ 409 with `control_disabled`; pre-execution audit failure ⇒ 500 and the fake was **not called**; dry-run with the fake returning `DryRunOk` ⇒ 200 with `agent_validated:true`; dry-run when `Offline` ⇒ 200 with today's preview and `agent_validated:false`; the four non-activated actions still ⇒ 501; tenant user addressing another tenant's host ⇒ 404 and fake not called; restore requires `quarantine_id`. In `composed_router_auth.rs`: restore route 401/403/allowed like the other response routes.
- [ ] **Step 2: Run** `cargo test -p osiris-response -p osiris-api` → fail.
- [ ] **Step 3: Implement.** In the handler, only `TerminateProcess`/`QuarantineFile`/`RestoreFile` take the remote branch (async, after the pre-audit, **not** inside `spawn_blocking`); other actions keep the current `dispatch()` path. Resolve the sample event through the tenant-scoped storage exactly as the dry-run path does today (reuse `events_for_entity`; pick the newest event carrying the needed field). Audit `why` after execution includes the agent detail (`quarantine_id`, `sha256`, signal) and for failures the code. Map outcomes to HTTP as in spec §5.
- [ ] **Step 4: Run** full `cargo test -p osiris-response -p osiris-api`; clippy.
- [ ] **Step 5: Commit** `feat(response): route TerminateProcess/QuarantineFile/RestoreFile through the command channel`.

---

### Task 7: CLI commands + operator docs

**Files:**
- Modify: `crates/osiris-cli/src/main.rs`, `client.rs` (+ tests in `crates/osiris-cli/tests/`)
- Create: `docs/operators-response-actions.md`

**Interfaces:** consumes the API from Task 6. Produces `osiris response terminate-process --pid-target <process_key> --reason <r> [--dry-run]`, `osiris response quarantine-file --file <inode:device:host> ...`, `osiris response restore-file --host <uuid> --quarantine-id <uuid> --reason <r> [--dry-run]` (thin `post_json` wrappers, token attached like other `--server` commands; follow `Incidents`/`Evidence` subcommand style).

- [ ] **Step 1: Failing tests** mirroring existing CLI tests (mock server): correct path/body per subcommand, `--reason` required, non-2xx surfaces the server's message.
- [ ] **Step 2-4: Implement, run, clippy.**
- [ ] **Step 5: Docs** `docs/operators-response-actions.md`: enabling (`control` on server and agent), `osiris pki init-command-key`, where the private key must live (server only, 0600, never on agents), agent config line for `command_public_key`, what each action does, protected targets, restore procedure, irreversibility of terminate, offline behaviour (409, no queueing), status codes table, and the Linux-validation caveat.
- [ ] **Step 6: Commit** `feat(cli,docs): response action commands and operator guide`.

---

### Task 8: End-to-end tests over the real control channel

**Files:**
- Modify: `crates/osiris-e2e-tests/tests/end_to_end.rs` (or new `tests/control_channel.rs`), `crates/osiris-e2e-tests/Cargo.toml`

**Interfaces:** consumes everything; uses `FakeExecutor` in an in-process agent control client (no OS-level actions).

- [ ] **Step 1: Failing tests** with a real authenticated router (`mint_admin_session` helper as in the other e2e tests), a real `ControlListener` + `run_control_client` with `AgentCommandHandler{FakeExecutor}`: (a) terminate happy path returns 200 and the fake saw exactly the expected `pid/exe_path/observed_at`; (b) quarantine then restore with the quarantine id from the first response; (c) agent not connected ⇒ 409; (d) replayed signed command sent straight through the hub is `Refused{Replay}`; (e) a command signed by a **different** key is `Refused{BadSignature}` and the fake is untouched; (f) every case leaves exactly two audit entries.
- [ ] **Step 2: Run** → fail, implement missing glue only, run → pass.
- [ ] **Step 3: Full verification:** `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo build -p osiris-cli -p osiris-server -p osiris-agent`, `cargo test --workspace` (read the whole summary), console unaffected.
- [ ] **Step 4: Commit** `test(e2e): command channel scenarios`.

---

## Self-Review (spec coverage)

* §2 architecture → Tasks 1-3, 5. §3 envelope/trust → Tasks 1-2. §4 agent execution + protected targets + dry-run → Tasks 2, 4. §5 server flow, status mapping, tenancy, restore → Task 6. §6 config/CLI/docs → Tasks 4, 5, 7. §7 security requirements → covered by guard/runner tests (Task 2), executor identity tests (Task 4), e2e (Task 8) and the dedicated opus review after Task 8. §8 testing → per-task tests + Task 8.
* Type consistency: `CommandAction`, `CommandResult`, `ExecDetail`, `Refusal`, `FailCode`, `SendError`, `DispatchError` are defined once (Tasks 1, 2, 3, 5) and only referenced afterwards; `RestoreFile` is added to `ResponseActionKind` in Task 6 and to the RBAC prefix in the same task.
* Known gap to record: Linux executor tests cannot run on the Windows dev host.
