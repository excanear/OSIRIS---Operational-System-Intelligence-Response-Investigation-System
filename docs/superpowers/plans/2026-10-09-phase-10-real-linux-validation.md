# Phase 10 — Real-Linux Validation, Benchmarks, Browser Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the production OSIRIS binaries against a real Linux kernel + auditd with an automated harness, fix what breaks, measure performance into `PERFORMANCE.md`, and verify the Console in a real browser with Playwright.

**Architecture:** A new dev-tooling crate `osiris-real-linux-tests` holds a synchronous harness library (YAML config rendering, PKI, bootstrap-admin session, child-process spawning, bounded API polling), the `#[ignore]` real-Linux scenario tests, and an `osiris-stack` binary that serves a seeded server for Playwright. A new `osiris-bench` crate reuses the harness for ingest/agent benchmarks. The Console gets a `@playwright/test` suite in `console/e2e/`.

**Tech Stack:** Rust (workspace, reqwest blocking, rusqlite, serde_yaml), bash (setup/run scripts, auditd rules), WSL2 Ubuntu-24.04 + Debian, TypeScript + `@playwright/test` (Chromium).

**Spec:** `docs/superpowers/specs/2026-10-09-phase-10-real-linux-validation-design.md`

## Global Constraints

1. Server and Agent configs are **YAML** (`serde_yaml`) — `ServerConfig::load` / `AgentConfig::load`; binaries take the config path as `argv[1]`.
2. The Agent binary always uses host id file `/etc/osiris/host_id` (`HostIdentity::load_or_create`); the agent mTLS certificate must be issued for that UUID.
3. The Server always tails its `spool_path` (NDJSON, one `CanonicalEvent` per line) in addition to the optional mTLS agent listener.
4. Real-Linux tests: every test `#[ignore]` and `#[cfg(target_os = "linux")]`, run serially (`--test-threads=1`) as root; `cargo test --workspace` must stay green on Windows and in CI.
5. Every wait is bounded; on timeout, panic with the last API body and the tail (last 60 lines) of both process logs.
6. Tests filter on unique markers, never on counts of host activity.
7. No new CI gates. CI keeps `perf_smoke`; real-Linux, bench and Playwright run locally/WSL.
8. Every fixed real-Linux finding gets a regression test that runs in normal CI on any OS (fixture-based).
9. Before merge: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `bash tools/check-dep-graph.sh`, console `npm run lint && npm test && npm run build`.
10. Out of scope: container/k8s scenarios, RHEL-like distros, DNS (no real DNS sensor exists), eBPF.
11. WSL access from Windows: `wsl -d Ubuntu-24.04 -- bash -lc "<cmd>"`; the repo is at `/mnt/f/Projetos/OSIRIS - Operational-System-Intelligence-Response-Investigation-System` (quote it — the path has spaces). Build Linux artifacts into a Linux-side target dir (`CARGO_TARGET_DIR=/root/osiris-target`) — never into the Windows `target/`.

## Review Focus

1. **A rendered config the binary rejects** — a typo in the YAML renderer must fail in a unit test, not as a 30 s timeout in WSL. Task 1 parses every rendered file with the real `ServerConfig::load` / `AgentConfig::load`.
2. **Stale `/etc/osiris/host_id` or a previous run's leftovers** — a second run on the same machine must still work (host id reused, temp dirs fresh, transient units/files removed). Task 3's tests clean up in a guard; Task 4 runs the suite twice in a row.
3. **The child binary dies at startup** (port in use, bad cert) — the harness must report the child's exit status and log, not wait out the deadline. Task 1's `wait_ready` checks `try_wait()` each poll and has a unit test with a binary that exits immediately.
4. **Bench pacing drift / zero-sample percentiles** — `percentile(&[])` and a rate the driver cannot sustain must produce an explicit result (None / "achieved X of Y"), not a panic or a fake number. Task 6 unit tests both.
5. **Playwright against an empty screen** — screens whose data the seed does not produce (hosts, sensors) must still pass on heading + no errors, while data screens must assert a seeded row so a silently-empty API is caught. Task 10's screen table encodes which is which.

---

## File Structure

```text
crates/osiris-real-linux-tests/
  Cargo.toml
  src/lib.rs            pub mod json; pub mod paths; pub mod render; pub mod stack; pub mod seed;
  src/json.rs           contains_str / has_kv over serde_json::Value
  src/paths.rs          workspace_root(), bin_path(), free_port()
  src/render.rs         ServerYaml / AgentYaml -> String (pure)
  src/stack.rs          Stack: PKI, users, spawn, wait_ready, api_get, wait_for, Drop
  src/seed.rs           generator scenarios -> NDJSON lines (for osiris-stack)
  src/bin/osiris-stack.rs
  tests/real_linux.rs   8 scenario tests (Linux, #[ignore])
crates/osiris-agent/src/host_info.rs     distro + kernel detection (new)
crates/osiris-agent/src/main.rs          use host_info
crates/osiris-bench/
  Cargo.toml
  src/main.rs           clap subcommands
  src/stats.rs          percentile, summarize, Pacer, parse_proc_stat, parse_vm_rss
  src/pipeline.rs       pipeline bench
  src/query.rs          query bench
  src/ingest.rs         ingest bench (server binary + run_forwarder + marker sampler)
  src/agent.rs          agent bench (Linux)
tools/real-linux/setup.sh, osiris.rules, run.sh, bench.sh
tools/check-dep-graph.sh                 forbid shipped crates depending on dev tooling
console/playwright.config.ts, console/e2e/*.ts, console/package.json (scripts, devDep)
docs/VALIDATION.md, PERFORMANCE.md, docs/ROADMAP-REMAINING.md
```

---

### Task 1: Harness library (`osiris-real-linux-tests`)

**Files:**
- Create: `crates/osiris-real-linux-tests/Cargo.toml`, `src/lib.rs`, `src/json.rs`, `src/paths.rs`, `src/render.rs`, `src/stack.rs`
- Modify: `tools/check-dep-graph.sh` (append checks)

**Interfaces:**
- Produces (used by Tasks 3, 7, 9):
  - `json::contains_str(v: &Value, needle: &str) -> bool` — true if any string anywhere in `v` contains `needle`.
  - `json::has_kv(v: &Value, key: &str, want: &Value) -> bool` — true if any object anywhere in `v` has `key` equal to `want`.
  - `paths::workspace_root() -> PathBuf`, `paths::bin_path(name: &str) -> PathBuf` (`$OSIRIS_BIN_DIR` or `<root>/target/release`, `.exe` on Windows), `paths::free_port() -> u16`.
  - `render::ServerYaml { dir: PathBuf, api_port: u16, agent_port: u16, control_port: u16, rules_dir: PathBuf, risk_weights: PathBuf, dev_cors: bool }` with `fn render(&self) -> String`.
  - `render::AgentYaml { dir: PathBuf, agent_port: u16, control_port: u16, audit_log: Option<PathBuf>, persistence_dirs: Vec<PathBuf>, health_interval_secs: u64 }` with `fn render(&self) -> String`.
  - `stack::StackOptions { agent: Option<AgentOptions>, api_port: Option<u16>, dev_cors: bool, bench_agent: Option<Uuid> }` (`bench_agent`: issue `pki/agent.{pem,key}` for this UUID without starting an agent — used by the ingest bench)`, `stack::AgentOptions { audit_log: PathBuf, persistence_dirs: Vec<PathBuf> }`.
  - `stack::Stack::start(opts: StackOptions) -> Stack`; fields/methods: `dir() -> &Path`, `base_url() -> &str`, `token() -> &str`, `admin_password() -> &str`, `host_id() -> Option<Uuid>` (agent or bench_agent id), `agent_addr() -> String` (`127.0.0.1:<agent listener port>`), `spool_path() -> PathBuf`, `events_db() -> PathBuf`, `api_get(path: &str) -> Value`, `wait_for(path: &str, deadline: Duration, done: impl Fn(&Value) -> bool) -> Value`, `logs_tail() -> String`, `agent_pid() -> Option<u32>`, `server_pid() -> u32`.

- [ ] **Step 1: Create the crate manifest and register it**

`crates/osiris-real-linux-tests/Cargo.toml` (the workspace glob `crates/*` already includes it):

```toml
[package]
name = "osiris-real-linux-tests"
version.workspace = true
edition.workspace = true
publish = false

[dependencies]
reqwest = { workspace = true }
serde_json = { workspace = true }
tempfile = { workspace = true }
uuid = { workspace = true }
osiris-auth = { path = "../osiris-auth" }
osiris-transport = { path = "../osiris-transport" }
osiris-command = { path = "../osiris-command" }
osiris-config = { path = "../osiris-config" }
osiris-generator = { path = "../../generator" }
osiris-pipeline = { path = "../osiris-pipeline" }
osiris-schema = { path = "../osiris-schema" }

[dev-dependencies]
osiris-server = { path = "../osiris-server" }
osiris-agent = { path = "../osiris-agent" }
```

`src/lib.rs`:

```rust
//! Phase 10 dev tooling: drives the production `osiris-server` / `osiris-agent`
//! binaries as child processes. Nothing shipped depends on this crate.
pub mod json;
pub mod paths;
pub mod render;
pub mod seed;
pub mod stack;
```

Create an empty `src/seed.rs` containing only `//! Filled in by Task 9.` so the crate compiles.

- [ ] **Step 2: Write failing tests for `json` and `render`**

`src/json.rs` test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn contains_str_finds_a_needle_nested_anywhere() {
        let v = json!([{"a": {"b": ["x", "has osiris-abc123 inside"]}}]);
        assert!(contains_str(&v, "osiris-abc123"));
        assert!(!contains_str(&v, "osiris-zzz"));
    }

    #[test]
    fn has_kv_matches_numbers_and_strings_in_nested_objects() {
        let v = json!([{"network": {"dst_port": 4242, "proto": "tcp"}}]);
        assert!(has_kv(&v, "dst_port", &json!(4242)));
        assert!(!has_kv(&v, "dst_port", &json!(4243)));
        assert!(has_kv(&v, "proto", &json!("tcp")));
    }
}
```

`src/render.rs` test module — parses the rendered YAML with the **real** loaders:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_server_yaml_loads_with_the_real_server_config() {
        let dir = tempfile::tempdir().unwrap();
        let y = ServerYaml {
            dir: dir.path().to_path_buf(),
            api_port: 18080,
            agent_port: 18081,
            control_port: 18082,
            rules_dir: dir.path().join("rules"),
            risk_weights: dir.path().join("weights.yaml"),
            dev_cors: true,
        };
        let path = dir.path().join("server.yaml");
        std::fs::write(&path, y.render()).unwrap();
        let cfg = osiris_server::ServerConfig::load(&path).unwrap();
        assert_eq!(cfg.listen_addr, "127.0.0.1:18080");
        assert_eq!(cfg.agent_listener.unwrap().listen_addr, "127.0.0.1:18081");
        assert_eq!(cfg.control.unwrap().listen_addr, "127.0.0.1:18082");
        assert_eq!(cfg.dev_cors, Some(true));
    }

    #[test]
    fn rendered_agent_yaml_loads_with_the_real_agent_config() {
        let dir = tempfile::tempdir().unwrap();
        let y = AgentYaml {
            dir: dir.path().to_path_buf(),
            agent_port: 18081,
            control_port: 18082,
            audit_log: Some("/var/log/audit/audit.log".into()),
            persistence_dirs: vec![dir.path().join("units")],
            health_interval_secs: 5,
        };
        let path = dir.path().join("agent.yaml");
        std::fs::write(&path, y.render()).unwrap();
        let cfg = osiris_agent::AgentConfig::load(&path).unwrap();
        assert_eq!(cfg.audit_log_path.as_deref(), Some("/var/log/audit/audit.log"));
        assert_eq!(cfg.fs_audit_log_path.as_deref(), Some("/var/log/audit/audit.log"));
        assert_eq!(cfg.identity_audit_log_path.as_deref(), Some("/var/log/audit/audit.log"));
        assert_eq!(cfg.systemd_audit_log_path.as_deref(), Some("/var/log/audit/audit.log"));
        assert_eq!(cfg.persistence_watch_paths.len(), 1);
        assert_eq!(cfg.fleet.health_interval_secs, 5);
        assert!(!cfg.enable_synthetic);
        assert_eq!(cfg.forward.unwrap().server_addr, "127.0.0.1:18081");
    }

    #[test]
    fn paths_with_spaces_and_backslashes_survive_rendering() {
        let dir = std::path::PathBuf::from(r"C:\Program Files\osiris dir");
        let y = AgentYaml {
            dir,
            agent_port: 1,
            control_port: 2,
            audit_log: None,
            persistence_dirs: vec![],
            health_interval_secs: 5,
        };
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("a.yaml");
        std::fs::write(&p, y.render()).unwrap();
        let cfg = osiris_agent::AgentConfig::load(&p).unwrap();
        assert_eq!(cfg.spool_path, r"C:\Program Files\osiris dir/agent-spool.ndjson");
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p osiris-real-linux-tests --lib`
Expected: compile errors (`contains_str`, `ServerYaml` not defined).

- [ ] **Step 4: Implement `json.rs`, `paths.rs`, `render.rs`**

`src/json.rs`:

```rust
//! Structure-agnostic searches over API responses, so scenario tests key on
//! their unique marker rather than on response shapes.
use serde_json::Value;

pub fn contains_str(v: &Value, needle: &str) -> bool {
    match v {
        Value::String(s) => s.contains(needle),
        Value::Array(a) => a.iter().any(|x| contains_str(x, needle)),
        Value::Object(o) => o.values().any(|x| contains_str(x, needle)),
        _ => false,
    }
}

pub fn has_kv(v: &Value, key: &str, want: &Value) -> bool {
    match v {
        Value::Array(a) => a.iter().any(|x| has_kv(x, key, want)),
        Value::Object(o) => {
            o.get(key) == Some(want) || o.values().any(|x| has_kv(x, key, want))
        }
        _ => false,
    }
}
```

`src/paths.rs`:

```rust
use std::path::PathBuf;

/// Repo root (this crate lives at `crates/osiris-real-linux-tests`).
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

/// A release binary: `$OSIRIS_BIN_DIR/<name>` or `<root>/target/release/<name>`.
pub fn bin_path(name: &str) -> PathBuf {
    let dir = std::env::var_os("OSIRIS_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target").join("release"));
    dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

/// A currently-free loopback port (bind :0, read, release).
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("bind :0")
        .port()
}
```

`src/render.rs` — YAML is written with every path single-quoted (YAML single quotes take backslashes literally; a `'` inside is doubled):

```rust
//! Renders server.yaml / agent.yaml for the production binaries. File names
//! inside `dir` are fixed; `stack.rs` writes the PKI/keys at the same names.
use std::path::{Path, PathBuf};

fn q(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', "''"))
}

fn f(dir: &Path, name: &str) -> String {
    // Forward slash join keeps Windows paths readable and valid.
    q(Path::new(&format!("{}/{}", dir.display(), name)))
}

pub struct ServerYaml {
    pub dir: PathBuf,
    pub api_port: u16,
    pub agent_port: u16,
    pub control_port: u16,
    pub rules_dir: PathBuf,
    pub risk_weights: PathBuf,
    pub dev_cors: bool,
}

impl ServerYaml {
    pub fn render(&self) -> String {
        let d = &self.dir;
        format!(
            "db_path: {db}\nspool_path: {spool}\nlisten_addr: '127.0.0.1:{api}'\n\
             rules_dir: {rules}\nrisk_weights_path: {risk}\n\
             baseline_db_path: {baseline}\nincidents_db_path: {inc}\nevidence_db_path: {ev}\n\
             links_db_path: {links}\ninvestigate_audit_log_path: {inv}\n\
             users_db_path: {users}\ntenants_db_path: {tenants}\nhosts_db_path: {hosts}\n\
             dev_cors: {cors}\n\
             agent_listener:\n  listen_addr: '127.0.0.1:{agent}'\n  cert: {scert}\n  key: {skey}\n  client_ca: {ca}\n\
             control:\n  listen_addr: '127.0.0.1:{control}'\n  cert: {scert}\n  key: {skey}\n  client_ca: {ca}\n  command_signing_key: {sign}\n",
            db = f(d, "events.db"),
            spool = f(d, "server-spool.ndjson"),
            api = self.api_port,
            rules = q(&self.rules_dir),
            risk = q(&self.risk_weights),
            baseline = f(d, "baseline.db"),
            inc = f(d, "incidents.db"),
            ev = f(d, "evidence.db"),
            links = f(d, "links.db"),
            inv = f(d, "investigate-audit.log"),
            users = f(d, "users.db"),
            tenants = f(d, "tenants.db"),
            hosts = f(d, "hosts.db"),
            cors = self.dev_cors,
            agent = self.agent_port,
            control = self.control_port,
            scert = f(d, "pki/server.pem"),
            skey = f(d, "pki/server.key"),
            ca = f(d, "pki/ca.pem"),
            sign = f(d, "keys/command.key"),
        )
    }
}

pub struct AgentYaml {
    pub dir: PathBuf,
    pub agent_port: u16,
    pub control_port: u16,
    pub audit_log: Option<PathBuf>,
    pub persistence_dirs: Vec<PathBuf>,
    pub health_interval_secs: u64,
}

impl AgentYaml {
    pub fn render(&self) -> String {
        let d = &self.dir;
        let mut s = format!(
            "spool_path: {spool}\nstatus_addr: '127.0.0.1:0'\nenable_synthetic: false\n\
             proc_root: '/proc'\nnetwork_proc_root: '/proc'\n\
             cloud_metadata:\n  enabled: false\n\
             fleet:\n  health_interval_secs: {hb}\n\
             forward:\n  server_addr: '127.0.0.1:{agent}'\n  server_name: 'localhost'\n  ca: {ca}\n  cert: {acert}\n  key: {akey}\n\
             control:\n  server_addr: '127.0.0.1:{control}'\n  server_name: 'localhost'\n  ca: {ca}\n  cert: {acert}\n  key: {akey}\n  command_public_key: {pubk}\n  vault_dir: {vault}\n",
            spool = f(d, "agent-spool.ndjson"),
            hb = self.health_interval_secs,
            agent = self.agent_port,
            control = self.control_port,
            ca = f(d, "pki/ca.pem"),
            acert = f(d, "pki/agent.pem"),
            akey = f(d, "pki/agent.key"),
            pubk = f(d, "keys/command.pub"),
            vault = f(d, "vault"),
        );
        if let Some(log) = &self.audit_log {
            for key in [
                "audit_log_path",
                "fs_audit_log_path",
                "identity_audit_log_path",
                "systemd_audit_log_path",
            ] {
                s.push_str(&format!("{key}: {}\n", q(log)));
            }
        }
        if !self.persistence_dirs.is_empty() {
            s.push_str("persistence_watch_paths:\n");
            for p in &self.persistence_dirs {
                s.push_str(&format!("  - path: {}\n    kind: systemd_unit_dir\n", q(p)));
            }
        }
        s
    }
}
```

Note `status_addr: 127.0.0.1:0` — if `serve_status` rejects port 0 the render test still passes (it only parses); Step 9 (Task 3 first live run) would reveal it — in that case use `paths::free_port()` and add an `AgentYaml.status_port: u16` field.

- [ ] **Step 5: Run the lib tests**

Run: `cargo test -p osiris-real-linux-tests --lib`
Expected: PASS (5 tests). If the agent test fails on an unknown field (e.g. `cloud_metadata.enabled` spelled differently), fix the renderer to match `crates/osiris-agent/src/config.rs` — the real loader is the authority.

- [ ] **Step 6: Write the failing `Stack` test (server-only mode, any OS)**

`src/stack.rs` test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Needs `cargo build --release -p osiris-server` first; skipped (not
    /// failed) when the binary is absent so plain `cargo test` stays green.
    #[test]
    fn server_only_stack_comes_up_and_serves_an_authenticated_api() {
        if !crate::paths::bin_path("osiris-server").exists() {
            eprintln!("skip: release osiris-server not built");
            return;
        }
        let stack = Stack::start(StackOptions::default());
        let hosts = stack.api_get("/api/v1/hosts");
        assert!(hosts.is_array(), "hosts body: {hosts}");
    }

    #[test]
    fn a_child_that_exits_at_startup_is_reported_immediately() {
        let started = std::time::Instant::now();
        let err = std::panic::catch_unwind(|| {
            wait_ready_or_exit(
                &mut std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("--this-flag-does-not-exist")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
                "probe",
                std::time::Duration::from_secs(20),
                || false,
                || String::new(),
            )
        });
        assert!(err.is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }
}
```

- [ ] **Step 7: Run to verify failure**

Run: `cargo test -p osiris-real-linux-tests --lib stack`
Expected: compile error (`Stack` not defined).

- [ ] **Step 8: Implement `stack.rs`**

```rust
//! Starts the real binaries with generated config. Server-only mode runs on
//! any OS; Agent mode is Linux-only (real auditd, /etc/osiris/host_id).
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use osiris_auth::{SqliteUserStore, UserStore};
use osiris_transport::pki::{generate_ca, issue_agent, issue_server, write_issued};
use serde_json::Value;
use uuid::Uuid;

use crate::paths::{bin_path, free_port, workspace_root};
use crate::render::{AgentYaml, ServerYaml};

#[derive(Default)]
pub struct StackOptions {
    pub agent: Option<AgentOptions>,
    /// Fixed API port (the Console stack needs 8080); free port when None.
    pub api_port: Option<u16>,
    pub dev_cors: bool,
    /// Issue an agent cert for this id without starting an agent (ingest bench).
    pub bench_agent: Option<Uuid>,
}

pub struct AgentOptions {
    pub audit_log: PathBuf,
    pub persistence_dirs: Vec<PathBuf>,
}

pub struct Stack {
    dir: tempfile::TempDir,
    base_url: String,
    token: String,
    admin_password: String,
    host_id: Option<Uuid>,
    agent_port: u16,
    server: Child,
    agent: Option<Child>,
    http: reqwest::blocking::Client,
}

const READY_DEADLINE: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(250);

fn tail(path: &Path, lines: usize) -> String {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    let v: Vec<&str> = s.lines().collect();
    v[v.len().saturating_sub(lines)..].join("\n")
}

/// Polls `ready` until true; panics at once if `child` has exited, or at
/// `deadline` with `logs()`.
pub(crate) fn wait_ready_or_exit(
    child: &mut Child,
    name: &str,
    deadline: Duration,
    ready: impl Fn() -> bool,
    logs: impl Fn() -> String,
) {
    let end = Instant::now() + deadline;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("{name} exited during startup ({status})\n{}", logs());
        }
        if ready() {
            return;
        }
        if Instant::now() >= end {
            panic!("{name} not ready within {deadline:?}\n{}", logs());
        }
        std::thread::sleep(POLL);
    }
}

impl Stack {
    pub fn start(opts: StackOptions) -> Stack {
        let dir = tempfile::Builder::new().prefix("osiris-p10-").tempdir().unwrap();
        let d = dir.path().to_path_buf();
        for sub in ["pki", "keys", "vault"] {
            std::fs::create_dir_all(d.join(sub)).unwrap();
        }

        // Agent mode binds the cert to the id the agent binary will read.
        let host_id = match (&opts.agent, opts.bench_agent) {
            (Some(_), _) => Some(
                osiris_config::HostIdentity::load_or_create(Path::new("/etc/osiris/host_id"))
                    .expect("/etc/osiris/host_id (run as root)"),
            ),
            (None, id) => id,
        };
        let ca = generate_ca("osiris-p10-ca").unwrap();
        write_issued(&d.join("pki"), "ca", &ca).unwrap();
        let server_cert = issue_server(
            &ca.cert_pem,
            &ca.key_pem,
            &["localhost".into(), "127.0.0.1".into()],
        )
        .unwrap();
        write_issued(&d.join("pki"), "server", &server_cert).unwrap();
        if let Some(h) = host_id {
            let a = issue_agent(&ca.cert_pem, &ca.key_pem, h).unwrap();
            write_issued(&d.join("pki"), "agent", &a).unwrap();
        }
        osiris_command::keys::write_signing_key(&d.join("keys"), "command").unwrap();

        let (users, bootstrap) = SqliteUserStore::open(d.join("users.db")).unwrap();
        let bootstrap = bootstrap.expect("fresh users.db has a bootstrap admin");
        let admin = users.get_user_by_username("admin").unwrap().unwrap();
        let token = users.create_session(admin.user_id, 86_400).unwrap().token;
        drop(users);

        let api_port = opts.api_port.unwrap_or_else(free_port);
        let (agent_port, control_port) = (free_port(), free_port());
        let root = workspace_root();
        let server_yaml = ServerYaml {
            dir: d.clone(),
            api_port,
            agent_port,
            control_port,
            rules_dir: root.join("config/rules"),
            risk_weights: root.join("config/risk/weights.yaml"),
            dev_cors: opts.dev_cors,
        };
        std::fs::write(d.join("server.yaml"), server_yaml.render()).unwrap();

        let server = spawn(&bin_path("osiris-server"), &d.join("server.yaml"), &d.join("server.log"));
        let mut stack = Stack {
            base_url: format!("http://127.0.0.1:{api_port}"),
            token,
            admin_password: bootstrap.password,
            host_id,
            agent_port,
            server,
            agent: None,
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            dir,
        };
        let url = format!("{}/api/v1/health", stack.base_url);
        let (http, token) = (stack.http.clone(), stack.token.clone());
        let logs_dir = d.clone();
        wait_ready_or_exit(
            &mut stack.server,
            "osiris-server",
            READY_DEADLINE,
            || {
                http.get(&url)
                    .bearer_auth(&token)
                    .send()
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
            },
            || format!("--- server.log ---\n{}", tail(&logs_dir.join("server.log"), 60)),
        );

        if let Some(a) = opts.agent {
            let agent_yaml = AgentYaml {
                dir: d.clone(),
                agent_port,
                control_port,
                audit_log: Some(a.audit_log),
                persistence_dirs: a.persistence_dirs,
                health_interval_secs: 5,
            };
            std::fs::write(d.join("agent.yaml"), agent_yaml.render()).unwrap();
            let mut child =
                spawn(&bin_path("osiris-agent"), &d.join("agent.yaml"), &d.join("agent.log"));
            let host = host_id.unwrap().to_string();
            let hosts_url = format!("{}/api/v1/hosts", stack.base_url);
            wait_ready_or_exit(
                &mut child,
                "osiris-agent",
                READY_DEADLINE,
                || {
                    http.get(&hosts_url)
                        .bearer_auth(&token)
                        .send()
                        .and_then(|r| r.json::<Value>())
                        .map(|v| crate::json::contains_str(&v, &host))
                        .unwrap_or(false)
                },
                || {
                    format!(
                        "--- server.log ---\n{}\n--- agent.log ---\n{}",
                        tail(&logs_dir.join("server.log"), 60),
                        tail(&logs_dir.join("agent.log"), 60)
                    )
                },
            );
            stack.agent = Some(child);
        }
        stack
    }

    pub fn dir(&self) -> &Path { self.dir.path() }
    pub fn base_url(&self) -> &str { &self.base_url }
    pub fn token(&self) -> &str { &self.token }
    pub fn admin_password(&self) -> &str { &self.admin_password }
    pub fn host_id(&self) -> Option<Uuid> { self.host_id }
    pub fn agent_addr(&self) -> String { format!("127.0.0.1:{}", self.agent_port) }
    pub fn spool_path(&self) -> PathBuf { self.dir.path().join("server-spool.ndjson") }
    pub fn events_db(&self) -> PathBuf { self.dir.path().join("events.db") }
    pub fn server_pid(&self) -> u32 { self.server.id() }
    pub fn agent_pid(&self) -> Option<u32> { self.agent.as_ref().map(|c| c.id()) }

    pub fn logs_tail(&self) -> String {
        format!(
            "--- server.log ---\n{}\n--- agent.log ---\n{}",
            tail(&self.dir.path().join("server.log"), 60),
            tail(&self.dir.path().join("agent.log"), 60)
        )
    }

    /// GET an API path with the admin session; non-2xx yields `Value::Null`.
    pub fn api_get(&self, path: &str) -> Value {
        self.http
            .get(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .send()
            .ok()
            .filter(|r| r.status().is_success())
            .and_then(|r| r.json().ok())
            .unwrap_or(Value::Null)
    }

    /// Bounded poll of `path` until `done`; panics with the last body + logs.
    pub fn wait_for(&self, path: &str, deadline: Duration, done: impl Fn(&Value) -> bool) -> Value {
        let end = Instant::now() + deadline;
        loop {
            let body = self.api_get(path);
            if done(&body) {
                return body;
            }
            if Instant::now() >= end {
                let mut s = body.to_string();
                s.truncate(4000);
                panic!("{path} never matched within {deadline:?}\nlast body: {s}\n{}", self.logs_tail());
            }
            std::thread::sleep(POLL);
        }
    }
}

fn spawn(bin: &Path, config: &Path, log: &Path) -> Child {
    assert!(bin.exists(), "{} missing — build with `cargo build --release`", bin.display());
    let out = File::create(log).unwrap();
    let err = out.try_clone().unwrap();
    Command::new(bin)
        .arg(config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", bin.display()))
}

impl Drop for Stack {
    fn drop(&mut self) {
        if let Some(a) = self.agent.as_mut() {
            let _ = a.kill();
            let _ = a.wait();
        }
        let _ = self.server.kill();
        let _ = self.server.wait();
        if std::thread::panicking() {
            let kept = std::mem::replace(
                &mut self.dir,
                tempfile::tempdir().unwrap(),
            )
            .into_path();
            eprintln!("stack dir kept for post-mortem: {}", kept.display());
        }
    }
}
```

- [ ] **Step 9: Build the server and run all lib tests**

Run: `cargo build --release -p osiris-server && cargo test -p osiris-real-linux-tests --lib`
Expected: PASS, including `server_only_stack_comes_up_and_serves_an_authenticated_api` (it actually starts the server on Windows). If `/api/v1/health` is unauthenticated the bearer header is harmless.

- [ ] **Step 10: Dependency-graph guard**

Append to `tools/check-dep-graph.sh` before its final exit check (follow the file's existing call style):

```bash
# Phase 10: dev tooling must never be reachable from shipped binaries.
check_forbidden osiris-server osiris-real-linux-tests osiris-bench
check_forbidden osiris-agent osiris-real-linux-tests osiris-bench
```

Run: `bash tools/check-dep-graph.sh` → Expected: exit 0.

- [ ] **Step 11: Clippy, fmt, commit**

```bash
cargo fmt --all && cargo clippy -p osiris-real-linux-tests --all-targets -- -D warnings
git add crates/osiris-real-linux-tests tools/check-dep-graph.sh Cargo.lock
git commit -m "feat(10): real-Linux harness library driving the production binaries"
```

---

### Task 2: Agent reports real distro and kernel

**Files:**
- Create: `crates/osiris-agent/src/host_info.rs`
- Modify: `crates/osiris-agent/src/lib.rs` (add `pub mod host_info;`), `crates/osiris-agent/src/main.rs:77-78`

**Interfaces:**
- Produces: `osiris_agent::host_info::distro_from_os_release(contents: &str) -> Option<String>`, `osiris_agent::host_info::detect() -> (String, String)` returning `(distro, kernel_version)`, each falling back to `"unknown"`.

- [ ] **Step 1: Failing tests**

`crates/osiris-agent/src/host_info.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_name_wins_and_quotes_are_stripped() {
        let s = "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n";
        assert_eq!(distro_from_os_release(s).as_deref(), Some("Ubuntu 24.04.3 LTS"));
    }

    #[test]
    fn falls_back_to_name_and_version_id_without_pretty_name() {
        let s = "NAME=Debian\nVERSION_ID='12'\n";
        assert_eq!(distro_from_os_release(s).as_deref(), Some("Debian 12"));
    }

    #[test]
    fn garbage_or_empty_yields_none() {
        assert_eq!(distro_from_os_release(""), None);
        assert_eq!(distro_from_os_release("# comment only\n"), None);
        assert_eq!(distro_from_os_release("PRETTY_NAME=\"\"\n"), None);
    }

    #[test]
    fn detect_never_returns_empty_strings() {
        let (d, k) = detect();
        assert!(!d.is_empty() && !k.is_empty());
    }
}
```

- [ ] **Step 2: Run** `cargo test -p osiris-agent host_info` → Expected: FAIL (functions missing).

- [ ] **Step 3: Implement**

```rust
//! Host facts the Agent reports in its HostRef (distro, kernel). Linux reads
//! /etc/os-release and /proc/sys/kernel/osrelease; anything unreadable falls
//! back to "unknown" so the Agent never fails to start over a cosmetic field.

fn unquote(v: &str) -> &str {
    let v = v.trim();
    v.strip_prefix('"').and_then(|x| x.strip_suffix('"'))
        .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
        .unwrap_or(v)
}

pub fn distro_from_os_release(contents: &str) -> Option<String> {
    let mut pretty = None;
    let mut name = None;
    let mut version = None;
    for line in contents.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = unquote(v).to_string();
        match k.trim() {
            "PRETTY_NAME" => pretty = Some(v),
            "NAME" => name = Some(v),
            "VERSION_ID" => version = Some(v),
            _ => {}
        }
    }
    if let Some(p) = pretty.filter(|p| !p.is_empty()) {
        return Some(p);
    }
    match (name.filter(|n| !n.is_empty()), version.filter(|v| !v.is_empty())) {
        (Some(n), Some(v)) => Some(format!("{n} {v}")),
        (Some(n), None) => Some(n),
        _ => None,
    }
}

pub fn detect() -> (String, String) {
    let distro = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| distro_from_os_release(&s))
        .unwrap_or_else(|| "unknown".to_string());
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    (distro, kernel)
}
```

In `main.rs`, replace the two hard-coded fields:

```rust
    let (distro, kernel_version) = osiris_agent::host_info::detect();
    let host = HostRef {
        host_id,
        hostname,
        distro,
        kernel_version,
        cloud,
    };
```

- [ ] **Step 4: Run** `cargo test -p osiris-agent host_info` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-agent/src/host_info.rs crates/osiris-agent/src/lib.rs crates/osiris-agent/src/main.rs
git commit -m "fix(10): agent reports the real distro and kernel instead of \"unknown\""
```

---

### Task 3: Real-Linux scripts and scenario tests

**Files:**
- Create: `tools/real-linux/setup.sh`, `tools/real-linux/osiris.rules`, `tools/real-linux/run.sh`, `crates/osiris-real-linux-tests/tests/real_linux.rs`

**Interfaces:**
- Consumes: Task 1 `Stack`, `StackOptions`, `AgentOptions`, `json::{contains_str, has_kv}`.
- Produces: `tools/real-linux/run.sh [cargo test filter]` — the entry point Tasks 4/5 run.

- [ ] **Step 1: Audit rules**

`tools/real-linux/osiris.rules`:

```text
## OSIRIS Phase 10 validation rules (loaded by setup.sh into /etc/audit/rules.d/)
## Process sensor: every execve.
-a always,exit -F arch=b64 -S execve -k osiris_exec
-a always,exit -F arch=b32 -S execve -k osiris_exec
## Filesystem sensor: writes/creates/renames/deletes under the watched trees.
-w /tmp/osiris-p10 -p wa -k osiris_fs
-w /var/www -p wa -k osiris_fs
-w /etc/systemd/system -p wa -k osiris_fs
## Identity/privilege: setuid/setgid family (USER_* records are on by default).
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid,setresuid,setresgid -k osiris_priv
```

If the fs sensor's parser expects specific syscalls rather than `-w` watches, read `crates/osiris-sensors/fs/src/assembler.rs` and adjust the rules to produce the record shapes it consumes; that adjustment is part of this step.

- [ ] **Step 2: `setup.sh`**

```bash
#!/usr/bin/env bash
# Prepares a WSL/VM Linux host for the OSIRIS real-Linux suite. Idempotent.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "setup.sh must run as root (auditd, /etc/osiris)"; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq auditd curl sudo build-essential pkg-config >/dev/null
mkdir -p /tmp/osiris-p10 /var/www /etc/osiris
install -m 0640 "$here/osiris.rules" /etc/audit/rules.d/osiris.rules
systemctl enable --now auditd >/dev/null
augenrules --load >/dev/null
auditctl -l | grep -q osiris_exec || { echo "audit rules did not load"; exit 1; }
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
fi
echo "ok: auditd $(auditctl -v | awk '{print $NF}'), $(systemctl --version | head -1), kernel $(uname -r)"
```

- [ ] **Step 3: `run.sh`**

```bash
#!/usr/bin/env bash
# Builds the release binaries into a Linux-side target dir and runs the
# real-Linux suite serially. Usage: run.sh [test-name-filter]
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run.sh must run as root"; exit 1; }
source "$HOME/.cargo/env" 2>/dev/null || true
root="$(cd "$(dirname "$0")/../.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/root/osiris-target}"
export OSIRIS_BIN_DIR="$CARGO_TARGET_DIR/release"
cd "$root"
cargo build --release -p osiris-server -p osiris-agent
cargo test --release -p osiris-real-linux-tests --test real_linux -- --ignored --test-threads=1 "$@"
```

`chmod +x` both scripts; run `git update-index --chmod=+x tools/real-linux/*.sh` (Windows checkout).

- [ ] **Step 4: Scenario tests**

`crates/osiris-real-linux-tests/tests/real_linux.rs`:

```rust
//! Phase 10 real-Linux scenarios. Run via `tools/real-linux/run.sh` as root
//! on a host prepared by `tools/real-linux/setup.sh`.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use osiris_real_linux_tests::json::{contains_str, has_kv};
use osiris_real_linux_tests::stack::{AgentOptions, Stack, StackOptions};
use serde_json::json;

const DEADLINE: Duration = Duration::from_secs(45);
const WATCH_ROOT: &str = "/tmp/osiris-p10";

fn marker() -> String {
    format!("osirisp10{}", uuid::Uuid::new_v4().simple())
}

fn now_ns() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

fn sh(script: &str) {
    let st = Command::new("/bin/bash").arg("-c").arg(script).status().unwrap();
    assert!(st.success(), "script failed: {script}");
}

/// One stack per test: agent on the real audit log, persistence watch on a
/// per-test dir under WATCH_ROOT.
fn stack(persist: &Path) -> Stack {
    std::fs::create_dir_all(persist).unwrap();
    Stack::start(StackOptions {
        agent: Some(AgentOptions {
            audit_log: PathBuf::from("/var/log/audit/audit.log"),
            persistence_dirs: vec![persist.to_path_buf()],
        }),
        ..Default::default()
    })
}

fn events(stack: &Stack, event_type: &str, since: u128, done: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
    stack.wait_for(
        &format!("/api/v1/events?event_type={event_type}&since={since}&limit=1000"),
        DEADLINE,
        done,
    )
}

/// Removes paths even when an assertion panics.
struct Cleanup(Vec<String>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        for c in &self.0 {
            let _ = Command::new("/bin/bash").arg("-c").arg(c).status();
        }
    }
}

#[test]
#[ignore]
fn exec_is_observed() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(&m));
    let t0 = now_ns();
    sh(&format!("/bin/sh -c 'true {m}'"));
    events(&s, "PROCESS_EXEC", t0, |v| contains_str(v, &m));
}

#[test]
#[ignore]
fn file_lifecycle_is_observed() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(format!("{m}-p")));
    let a = format!("{WATCH_ROOT}/{m}.txt");
    let b = format!("{WATCH_ROOT}/{m}.renamed");
    let _c = Cleanup(vec![format!("rm -f {a} {b}")]);
    let t0 = now_ns();
    sh(&format!("echo hi > {a} && echo more >> {a} && mv {a} {b} && rm {b}"));
    events(&s, "FILE_CREATE", t0, |v| contains_str(v, &a));
    events(&s, "FILE_WRITE", t0, |v| contains_str(v, &a) || contains_str(v, &b));
    events(&s, "FILE_RENAME", t0, |v| contains_str(v, &b));
    events(&s, "FILE_DELETE", t0, |v| contains_str(v, &b));
}

#[test]
#[ignore]
fn network_connect_is_observed() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(&m));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accept = std::thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_secs(8));
        drop(conn);
    });
    let t0 = now_ns();
    // Held open well past one /proc/net/tcp poll interval.
    sh(&format!("exec 3<>/dev/tcp/127.0.0.1/{port}; sleep 6; exec 3<&-"));
    events(&s, "NETWORK_CONNECT", t0, |v| has_kv(v, "dst_port", &json!(port)));
    accept.join().unwrap();
}

#[test]
#[ignore]
fn sudo_is_observed() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(&m));
    let t0 = now_ns();
    sh(&format!("sudo -u nobody /bin/sh -c 'true {m}'"));
    events(&s, "PRIVILEGE_SUDO", t0, |v| contains_str(v, &m));
}

#[test]
#[ignore]
fn systemd_unit_start_is_observed() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(&m));
    let unit = format!("osiris-{m}");
    let _c = Cleanup(vec![format!("systemctl reset-failed {unit}.service 2>/dev/null; true")]);
    let t0 = now_ns();
    sh(&format!("systemd-run --unit {unit} --wait /bin/true"));
    events(&s, "SERVICE_START", t0, |v| contains_str(v, &unit));
}

#[test]
#[ignore]
fn persistence_write_is_observed() {
    let m = marker();
    let dir = Path::new(WATCH_ROOT).join(format!("{m}-units"));
    let s = stack(&dir);
    let unit = dir.join(format!("{m}.service"));
    let t0 = now_ns();
    std::fs::write(&unit, "[Service]\nExecStart=/bin/true\n").unwrap();
    events(&s, "PERSISTENCE_CREATED", t0, |v| contains_str(v, &m));
}

#[test]
#[ignore]
fn web_root_drop_raises_an_alert() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(&m));
    let path = format!("/var/www/{m}.php");
    let _c = Cleanup(vec![format!("rm -f {path}")]);
    let t0 = now_ns();
    sh(&format!("/bin/bash -c 'echo \"<?php system($_GET[c]); ?>\" > {path}'"));
    s.wait_for(
        &format!("/api/v1/alerts?rule_id=shell_wrote_file_to_web_root&since={t0}"),
        DEADLINE,
        |v| contains_str(v, &m),
    );
}

#[test]
#[ignore]
fn agent_reports_real_host_facts_and_healthy_sensors() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(&m));
    let host = s.host_id().unwrap().to_string();
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let hosts = s.wait_for("/api/v1/hosts", DEADLINE, |v| contains_str(v, &host));
    assert!(contains_str(&hosts, kernel.trim()), "kernel missing: {hosts}");
    assert!(!has_kv(&hosts, "distro", &json!("unknown")), "distro unknown: {hosts}");
    let health = events(&s, "AGENT_HEALTH", 0, |v| v.as_array().is_some_and(|a| !a.is_empty()));
    for sensor in ["process", "filesystem", "network", "identity", "systemd", "persistence"] {
        assert!(contains_str(&health, sensor), "sensor {sensor} absent from AGENT_HEALTH: {health}");
    }
    assert!(!contains_str(&health, "FAILED"), "a sensor reports FAILED: {health}");
}
```

The sensor-name strings must match what each sensor's `name()` returns — check `crates/osiris-sensors/*/src/sensor.rs` and correct the list before running. Likewise confirm `/api/v1/events` accepts `since` in nanoseconds (`EventsQuery` in `crates/osiris-api/src/lib.rs:242`) — if it takes another unit, convert in `events()`.

- [ ] **Step 5: Verify it compiles on Windows (empty) and in WSL**

Run (Windows): `cargo test -p osiris-real-linux-tests` → PASS (no real-Linux tests compiled).
Run (WSL): `wsl -d Ubuntu-24.04 -- bash -lc "cd '/mnt/f/Projetos/OSIRIS - Operational-System-Intelligence-Response-Investigation-System' && tools/real-linux/setup.sh && CARGO_TARGET_DIR=/root/osiris-target cargo test -p osiris-real-linux-tests --no-run"` → compiles.

- [ ] **Step 6: Commit**

```bash
git add tools/real-linux crates/osiris-real-linux-tests/tests
git commit -m "test(10): real-Linux scenario suite and WSL setup/run scripts"
```

(Tests are expected to fail on first live run — that is Task 4.)

---

### Task 4: Discover and fix on Ubuntu-24.04

**Files:** depend on findings. Fixtures go in the owning crate (e.g. `crates/osiris-sensors/fs/tests/fixtures/ubuntu2404-*.log`); rule fixes in `config/rules/*.yaml` + their existing tests in `crates/osiris-detect`.

**Interfaces:** none new; must keep every existing public signature.

- [ ] **Step 1: First live run**

Run: `wsl -d Ubuntu-24.04 -- bash -lc "cd '/mnt/f/Projetos/OSIRIS - Operational-System-Intelligence-Response-Investigation-System' && tools/real-linux/run.sh"`
Record every failing test and its panic output into the SDD ledger.

- [ ] **Step 2: For each failure, capture the real input**

E.g. for a filesystem failure: `ausearch -k osiris_fs -ts recent --raw > /tmp/fs.log`, keep the records for the marker, scrub nothing (it is a throwaway test host), save as a fixture in the sensor crate.

- [ ] **Step 3: Failing unit test against the fixture**

In the sensor crate's tests, feed the fixture lines through the same parser/assembler the sensor uses and assert the expected `RawEvent`s — e.g.:

```rust
#[test]
fn ubuntu_2404_create_write_rename_delete_records_assemble_into_four_events() {
    let lines = include_str!("fixtures/ubuntu2404-file-lifecycle.log");
    let mut asm = Assembler::new();
    let events: Vec<_> = lines.lines().flat_map(|l| asm.feed(l)).collect();
    let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, [FileOp::Create, FileOp::Write, FileOp::Rename, FileOp::Delete]);
}
```

(Use the crate's actual type names; the shape above is the pattern.) Run it → FAIL for the right reason.

- [ ] **Step 4: Fix at the root, run the unit test → PASS, re-run the real-Linux test → PASS.**

Expected known finding — **merged-/usr exe paths**: on Ubuntu the kernel reports `/usr/bin/bash` / `/usr/bin/dash` for `/bin/bash` / `/bin/sh`. Fix `config/rules/shell_wrote_file_to_web_root.yaml` (and any other rule listing `/bin/...` exes — grep `config/rules` for `"/bin/`) to list both spellings, e.g. `["/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/curl", "/usr/bin/wget"]`, with a detect-crate test that a `/usr/bin/bash` writer under `/var/www/` matches.

- [ ] **Step 5: Commit each finding separately**

`git commit -m "fix(10): <sensor/rule>: <what real Linux does that synthetic tests missed>"`

- [ ] **Step 6: Stability check** — run the full suite twice back-to-back; both runs green. Anything flaky is a finding (timing) and gets fixed or documented.

- [ ] **Step 7: Scope valve** — a finding whose fix would exceed ~one plan task is written up (symptom, raw evidence, suspected cause) for `docs/VALIDATION.md` "Deferred" and its test is marked `#[ignore = "deferred: <reason>, see docs/VALIDATION.md"]` — never deleted.

---

### Task 5: Debian run and `docs/VALIDATION.md`

**Files:**
- Create: `docs/VALIDATION.md`
- Modify: anything Debian findings require (same procedure as Task 4).

- [ ] **Step 1: Import Debian**

PowerShell: `wsl --install -d Debian --no-launch` then `wsl -d Debian -u root -- bash -lc "cat /etc/os-release | head -3"`. If systemd is not PID 1, write `/etc/wsl.conf` with `[boot]\nsystemd=true` and `wsl --terminate Debian`.

- [ ] **Step 2: Setup + run**

`wsl -d Debian -u root -- bash -lc "cd '/mnt/f/Projetos/OSIRIS - Operational-System-Intelligence-Response-Investigation-System' && tools/real-linux/setup.sh && tools/real-linux/run.sh"`. Fix failures exactly as in Task 4 Steps 2-7 (fixture names prefixed `debian<ver>-`).

- [ ] **Step 3: Write `docs/VALIDATION.md`**

Sections: `# Real-Linux validation (Phase 10)`; `## How to reproduce` (setup.sh / run.sh commands, root, WSL notes); one `## <Distro>` section per distro with a versions table (distro, kernel, auditd, systemd, date) and the 8-row pass/fail table; `## Findings` table (finding, distro, fix commit or "deferred"); `## Deferred`; `## Console` (filled by Task 11); `## Known gaps` (no DNS sensor, no container/k8s scenarios, RHEL-like not covered).

- [ ] **Step 4: Commit** `git commit -m "docs(10): real-Linux validation report (Ubuntu 24.04, Debian)"`

---

### Task 6: `osiris-bench` core (stats, pipeline, query)

**Files:**
- Create: `crates/osiris-bench/Cargo.toml`, `src/main.rs`, `src/stats.rs`, `src/pipeline.rs`, `src/query.rs`

**Interfaces:**
- Produces: `stats::percentile(sorted: &[f64], p: f64) -> Option<f64>`, `stats::Summary { n: usize, p50: Option<f64>, p95: Option<f64>, p99: Option<f64>, max: Option<f64> }`, `stats::summarize(samples: &mut Vec<f64>) -> Summary`, `stats::Pacer::new(rate_per_sec: u64)` with `fn due(&mut self, elapsed: Duration) -> u64` (events to emit now so total emitted tracks `rate * elapsed`), `stats::parse_proc_stat_ticks(stat: &str) -> Option<u64>` (utime+stime), `stats::parse_vm_rss_kib(status: &str) -> Option<u64>`, `stats::Record` (serde-serializable result line: `bench: String, params: serde_json::Value, metrics: serde_json::Value`).

- [ ] **Step 1: Manifest**

```toml
[package]
name = "osiris-bench"
version.workspace = true
edition.workspace = true
publish = false

[dependencies]
clap = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
tokio-util = { workspace = true }
uuid = { workspace = true }
rusqlite = { workspace = true }
tempfile = { workspace = true }
osiris-pipeline = { path = "../osiris-pipeline" }
osiris-schema = { path = "../osiris-schema" }
osiris-sensor-api = { path = "../osiris-sensor-api" }
osiris-storage = { path = "../osiris-storage" }
osiris-storage-sqlite = { path = "../osiris-storage-sqlite" }
osiris-transport = { path = "../osiris-transport" }
osiris-generator = { path = "../../generator" }
osiris-real-linux-tests = { path = "../osiris-real-linux-tests" }
```

- [ ] **Step 2: Failing stats tests** (`src/stats.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn percentile_of_empty_is_none_not_a_panic() {
        assert_eq!(percentile(&[], 50.0), None);
        assert_eq!(summarize(&mut vec![]).p99, None);
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let mut v: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let s = summarize(&mut v);
        assert_eq!(s.p50, Some(50.0));
        assert_eq!(s.p95, Some(95.0));
        assert_eq!(s.p99, Some(99.0));
        assert_eq!(s.max, Some(100.0));
    }

    #[test]
    fn pacer_tracks_rate_times_elapsed_without_drift() {
        let mut p = Pacer::new(1000);
        let mut total = 0;
        for ms in 1..=1000 {
            total += p.due(Duration::from_millis(ms));
        }
        assert_eq!(total, 1000);
        assert_eq!(p.due(Duration::from_millis(1000)), 0);
    }

    #[test]
    fn proc_stat_ticks_survive_a_comm_with_spaces_and_parens() {
        // Fields after the last ')': state=3, ... utime=14, stime=15 (1-based in proc(5)).
        let stat = "4242 (osiris (a) b) S 1 4242 4242 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 9 0 100 0 0";
        assert_eq!(parse_proc_stat_ticks(stat), Some(300));
    }

    #[test]
    fn vm_rss_is_read_in_kib() {
        let status = "Name:\tosiris-agent\nVmPeak:\t  90000 kB\nVmRSS:\t   12345 kB\n";
        assert_eq!(parse_vm_rss_kib(status), Some(12345));
        assert_eq!(parse_vm_rss_kib("Name:\tx\n"), None);
    }
}
```

- [ ] **Step 3: Run** `cargo test -p osiris-bench` → FAIL (undefined).

- [ ] **Step 4: Implement `stats.rs`**

```rust
use std::time::Duration;

use serde::Serialize;

/// Nearest-rank percentile over an ascending slice; None when empty.
pub fn percentile(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    Some(sorted[rank.min(sorted.len()) - 1])
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Summary {
    pub n: usize,
    pub p50: Option<f64>,
    pub p95: Option<f64>,
    pub p99: Option<f64>,
    pub max: Option<f64>,
}

pub fn summarize(samples: &mut Vec<f64>) -> Summary {
    samples.sort_by(|a, b| a.total_cmp(b));
    Summary {
        n: samples.len(),
        p50: percentile(samples, 50.0),
        p95: percentile(samples, 95.0),
        p99: percentile(samples, 99.0),
        max: samples.last().copied(),
    }
}

/// Emits `rate * elapsed` events in total, however irregularly it is polled.
pub struct Pacer {
    rate: u64,
    emitted: u64,
}

impl Pacer {
    pub fn new(rate_per_sec: u64) -> Self {
        Self { rate: rate_per_sec, emitted: 0 }
    }

    pub fn due(&mut self, elapsed: Duration) -> u64 {
        let target = (self.rate as u128 * elapsed.as_millis() / 1000) as u64;
        let n = target.saturating_sub(self.emitted);
        self.emitted += n;
        n
    }
}

/// utime + stime (clock ticks) from /proc/<pid>/stat. Parses after the LAST
/// ')' because comm may contain spaces and parentheses.
pub fn parse_proc_stat_ticks(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // rest starts at field 3 (state); utime is field 14, stime 15.
    let utime: u64 = f.get(11)?.parse().ok()?;
    let stime: u64 = f.get(12)?.parse().ok()?;
    Some(utime + stime)
}

pub fn parse_vm_rss_kib(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

/// One machine-readable result line (printed as JSON).
#[derive(Debug, Serialize)]
pub struct Record {
    pub bench: String,
    pub params: serde_json::Value,
    pub metrics: serde_json::Value,
}
```

Run `cargo test -p osiris-bench` → PASS.

- [ ] **Step 5: `pipeline.rs` and `query.rs`**

`pipeline.rs` — `pub fn run(events: u64) -> Record`: build `Pipeline::new(HostRef{..}, "bench-boot")` exactly as `crates/osiris-e2e-tests/tests/perf_smoke.rs` does, cycle through the generator scenarios (`osiris_generator::{exec_chain_scenario, web_shell_drop_scenario, network_beacon_scenario, ssh_sudo_escalation_scenario, persistence_via_systemd_service_scenario}` with `base_ts_ns = i`), `black_box` each result, report `events_per_sec` and `elapsed_ms`.

`query.rs` — `pub fn run(events: u64) -> Record`: open `SqliteStorage::open(tempdir/events.db)`, generate `events` CanonicalEvents via the pipeline (same scenario cycle, pids varied by `i`), `batch_write` in chunks of 5000, then time (median of 5) three queries: `storage.query(&QueryPlan::new())` (default list, limit 100), `QueryPlan { event_type: Some(EventType::ProcessExec), ..QueryPlan::new() }`, and `storage.query_alerts(&AlertQueryPlan::new())`. Report `fill_ms` and each query's `median_ms`. Use `std::time::Instant`; median helper reuses `percentile(&sorted, 50.0)`.

- [ ] **Step 6: `main.rs` (clap)**

```rust
use clap::{Parser, Subcommand};

mod agent;
mod ingest;
mod pipeline;
mod query;
mod stats;

#[derive(Parser)]
#[command(about = "OSIRIS benchmarks (ARCHITECTURE.md §19.2) — results go to PERFORMANCE.md")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Pipeline { #[arg(long, default_value_t = 200_000)] events: u64 },
    Query { #[arg(long, default_value_t = 100_000)] events: u64 },
    Ingest { #[arg(long)] rate: u64, #[arg(long, default_value_t = 30)] duration: u64 },
    Agent { #[arg(long)] rate: u64, #[arg(long, default_value_t = 30)] duration: u64 },
    All,
}

fn main() {
    let records = match Cli::parse().cmd {
        Cmd::Pipeline { events } => vec![pipeline::run(events)],
        Cmd::Query { events } => vec![query::run(events)],
        Cmd::Ingest { rate, duration } => vec![ingest::run(rate, duration)],
        Cmd::Agent { rate, duration } => vec![agent::run(rate, duration)],
        Cmd::All => {
            let mut v = vec![pipeline::run(200_000)];
            for n in [10_000, 100_000, 1_000_000] { v.push(query::run(n)); }
            for r in [1_000, 10_000, 100_000] { v.push(ingest::run(r, 30)); }
            for r in [0, 1_000, 10_000] { v.push(agent::run(r, 30)); }
            v
        }
    };
    for r in &records {
        println!("{}", serde_json::to_string(r).unwrap());
    }
}
```

For this task create `ingest.rs` and `agent.rs` stubs whose `run` returns a `Record` with `metrics: {"skipped": "implemented in Task 7"}` so the binary builds — Task 7 replaces them.

- [ ] **Step 7: Smoke** `cargo run --release -p osiris-bench -- pipeline --events 20000` and `-- query --events 5000` print one JSON line each. Clippy clean.

- [ ] **Step 8: Commit** `git commit -m "feat(10): osiris-bench with pipeline and query benchmarks"`

---

### Task 7: Ingest and agent benchmarks

**Files:**
- Modify: `crates/osiris-bench/src/ingest.rs`, `crates/osiris-bench/src/agent.rs`
- Create: `tools/real-linux/bench.sh`

**Interfaces:**
- Consumes: Task 1 `Stack`, `StackOptions`, `AgentOptions`; Task 6 `stats::*`; `osiris_transport::client::{ForwarderConfig, run_forwarder}`.

- [ ] **Step 1: Failing test for the marker sampler** (in `ingest.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_latency_is_measured_from_send_to_first_visibility() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("events.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE events (event_id TEXT PRIMARY KEY)").unwrap();
        let id = uuid::Uuid::new_v4();
        let mut pending = vec![(id, std::time::Instant::now())];
        assert!(poll_markers(&db, &mut pending).is_empty());
        conn.execute("INSERT INTO events (event_id) VALUES (?1)", [id.to_string()]).unwrap();
        let seen = poll_markers(&db, &mut pending);
        assert_eq!(seen.len(), 1);
        assert!(pending.is_empty());
    }
}
```

Run → FAIL.

- [ ] **Step 2: Implement `ingest.rs`**

```rust
//! Ingest bench: real osiris-server binary, real mTLS forwarder, paced load.
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use osiris_real_linux_tests::stack::{Stack, StackOptions};
use uuid::Uuid;

use crate::stats::{summarize, Pacer, Record};

/// Returns latencies (ms) of markers now visible in events.db, removing them
/// from `pending`.
pub(crate) fn poll_markers(db: &Path, pending: &mut Vec<(Uuid, Instant)>) -> Vec<f64> {
    let Ok(conn) = rusqlite::Connection::open_with_flags(
        db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) else {
        return vec![];
    };
    let mut seen = vec![];
    pending.retain(|(id, sent)| {
        let found = conn
            .query_row("SELECT 1 FROM events WHERE event_id = ?1", [id.to_string()], |_| Ok(()))
            .is_ok();
        if found {
            seen.push(sent.elapsed().as_secs_f64() * 1000.0);
        }
        !found
    });
    seen
}

/// Server-only stack; the bench itself plays the agent, shipping over the
/// real mTLS listener with the real forwarder (`drive`, Step 3).
pub fn run(rate: u64, duration_s: u64) -> Record {
    let stack = Stack::start(StackOptions {
        bench_agent: Some(Uuid::new_v4()),
        ..Default::default()
    });
    drive(&stack, rate, duration_s)
}
```

- [ ] **Step 3: The driver** (same file; imports: `osiris_schema::HostRef`, `osiris_transport::client::{ForwarderConfig, run_forwarder}`)

```rust
fn drive(stack: &Stack, rate: u64, duration_s: u64) -> Record {
    let host = HostRef { host_id: stack.host_id().unwrap(), hostname: "bench".into(),
        distro: "bench".into(), kernel_version: "bench".into(), cloud: None };
    let mut pipeline = osiris_pipeline::Pipeline::new(host, "bench-boot".into());
    let spool = stack.dir().join("bench-spool.ndjson");
    std::fs::File::create(&spool).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let d = stack.dir();
    let cfg = ForwarderConfig::new(stack.agent_addr(), "localhost", d.join("pki/ca.pem"),
        d.join("pki/agent.pem"), d.join("pki/agent.key"), spool.clone());
    rt.spawn(run_forwarder(cfg, cancel.clone()));

    let mut out = std::fs::OpenOptions::new().append(true).open(&spool).unwrap();
    let mut pacer = Pacer::new(rate);
    let (start, end) = (Instant::now(), Duration::from_secs(duration_s));
    let mut sent = 0u64;
    let mut next_marker = Duration::ZERO;
    let mut pending = vec![];
    let mut latencies = vec![];
    let scenario = osiris_generator::exec_chain_scenario(0);
    while start.elapsed() < end {
        let n = pacer.due(start.elapsed());
        let mut buf = String::new();
        for _ in 0..n {
            let raw = scenario[(sent % scenario.len() as u64) as usize].clone();
            let ev = pipeline.process(raw).event;
            if start.elapsed() >= next_marker {
                pending.push((ev.event_id, Instant::now()));
                next_marker += Duration::from_millis(100);
            }
            buf.push_str(&serde_json::to_string(&ev).unwrap());
            buf.push('\n');
            sent += 1;
        }
        out.write_all(buf.as_bytes()).unwrap();
        latencies.extend(poll_markers(&stack.events_db(), &mut pending));
        std::thread::sleep(Duration::from_millis(5));
    }
    // Drain: give stragglers up to 30 s, then count the rest as not delivered.
    let drain_end = Instant::now() + Duration::from_secs(30);
    while !pending.is_empty() && Instant::now() < drain_end {
        latencies.extend(poll_markers(&stack.events_db(), &mut pending));
        std::thread::sleep(Duration::from_millis(50));
    }
    cancel.cancel();
    let achieved = sent as f64 / start.elapsed().min(end).as_secs_f64();
    let lat = summarize(&mut latencies);
    Record {
        bench: "ingest".into(),
        params: serde_json::json!({"rate": rate, "duration_s": duration_s}),
        metrics: serde_json::json!({"sent": sent, "achieved_eps": achieved,
            "markers_lost": pending.len(), "latency_ms": lat}),
    }
}
```

Note: `pipeline.process` is called inline, so at 100K eps the driver may itself be the bottleneck — the record shows `achieved_eps` honestly; do not "fix" by pre-generating unless the driver is clearly the cap, in which case pre-generate one 1 s batch and reuse it with fresh `event_id`s (document that in PERFORMANCE.md).

- [ ] **Step 4: Implement `agent.rs` (Linux-only body)**

```rust
//! Agent bench: real agent on real auditd, real exec load, /proc sampling.
use std::time::{Duration, Instant};

use crate::stats::{summarize, Pacer, Record};

#[cfg(not(target_os = "linux"))]
pub fn run(rate: u64, duration_s: u64) -> Record {
    Record { bench: "agent".into(),
        params: serde_json::json!({"rate": rate, "duration_s": duration_s}),
        metrics: serde_json::json!({"skipped": "linux only"}) }
}

#[cfg(target_os = "linux")]
pub fn run(rate: u64, duration_s: u64) -> Record {
    use osiris_real_linux_tests::stack::{AgentOptions, Stack, StackOptions};
    use crate::stats::{parse_proc_stat_ticks, parse_vm_rss_kib};

    let persist = tempfile::tempdir().unwrap();
    let stack = Stack::start(StackOptions {
        agent: Some(AgentOptions { audit_log: "/var/log/audit/audit.log".into(),
            persistence_dirs: vec![persist.path().to_path_buf()] }),
        ..Default::default()
    });
    let pid = stack.agent_pid().unwrap();
    let tick_hz = 100.0; // USER_HZ on Linux x86_64/arm64
    let read = || -> Option<(u64, u64)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        Some((parse_proc_stat_ticks(&stat)?, parse_vm_rss_kib(&status)?))
    };
    std::thread::sleep(Duration::from_secs(5)); // let startup settle
    let mut pacer = Pacer::new(rate);
    let start = Instant::now();
    let end = Duration::from_secs(duration_s);
    let (mut prev_ticks, _) = read().unwrap();
    let mut next_sample = Duration::from_secs(1);
    let (mut cpu, mut rss) = (vec![], vec![]);
    let mut spawned = 0u64;
    let mut children = vec![];
    while start.elapsed() < end {
        for _ in 0..pacer.due(start.elapsed()) {
            if let Ok(c) = std::process::Command::new("/bin/true").spawn() {
                children.push(c);
                spawned += 1;
            }
        }
        children.retain_mut(|c| !matches!(c.try_wait(), Ok(Some(_))));
        if start.elapsed() >= next_sample {
            if let Some((ticks, kib)) = read() {
                cpu.push((ticks - prev_ticks) as f64 / tick_hz * 100.0); // % of one core over 1 s
                rss.push(kib as f64 / 1024.0);
                prev_ticks = ticks;
            }
            next_sample += Duration::from_secs(1);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    for mut c in children { let _ = c.wait(); }
    let achieved = spawned as f64 / start.elapsed().as_secs_f64();
    Record {
        bench: "agent".into(),
        params: serde_json::json!({"rate": rate, "duration_s": duration_s}),
        metrics: serde_json::json!({"achieved_exec_per_sec": achieved,
            "cpu_pct_one_core": summarize(&mut cpu), "rss_mib": summarize(&mut rss)}),
    }
}
```

- [ ] **Step 5: `tools/real-linux/bench.sh`**

```bash
#!/usr/bin/env bash
# Runs the full benchmark matrix on a prepared host and keeps the JSON lines.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "bench.sh must run as root"; exit 1; }
source "$HOME/.cargo/env" 2>/dev/null || true
root="$(cd "$(dirname "$0")/../.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/root/osiris-target}"
export OSIRIS_BIN_DIR="$CARGO_TARGET_DIR/release"
cd "$root"
cargo build --release -p osiris-server -p osiris-agent -p osiris-bench
"$OSIRIS_BIN_DIR/osiris-bench" all | tee "${1:-/tmp/osiris-bench.jsonl}"
```

- [ ] **Step 6: Tests + smoke in WSL**

`cargo test -p osiris-bench` (Windows) → PASS. WSL: `osiris-bench ingest --rate 1000 --duration 10` and `osiris-bench agent --rate 100 --duration 10` each print a JSON line with non-null p50 / cpu samples.

- [ ] **Step 7: Commit** `git commit -m "feat(10): ingest and agent benchmarks over the real binaries"`

---

### Task 8: Run the matrix, write `PERFORMANCE.md`

**Files:** Create `PERFORMANCE.md` (repo root).

- [ ] **Step 1:** WSL Ubuntu: `tools/real-linux/bench.sh /tmp/bench-ubuntu.jsonl`. Capture hardware: `lscpu | grep 'Model name'`, `nproc`, `free -h`, `uname -r`, plus the Windows host CPU from `Get-CimInstance Win32_Processor | Select Name`.
- [ ] **Step 2:** Write `PERFORMANCE.md`: `## Methodology` (what each bench does, link ARCHITECTURE.md §19.2, release build, single run, 30 s each); `## Environment`; `## Results` — tables: pipeline (events/s), query (fill + 3 medians × 3 volumes), ingest (target vs achieved eps, p50/p95/p99 ms, markers lost × 3 rates), agent (exec/s achieved, CPU % mean-ish p50/p95, RSS MiB p50/max × 3 rates); `## Interpretation` (bottleneck observed, WSL2 caveats: virtualised disk under `/tmp`, shared host CPU, no isolation); `## Reproduce` (`tools/real-linux/bench.sh`). Fill tables from the JSON lines verbatim (round to 2 significant decimals).
- [ ] **Step 3:** If a result exposes a defect (e.g. markers lost at 1K eps, RSS growing unbounded), stop and treat it like a Task 4 finding (test + fix or deferred with evidence).
- [ ] **Step 4: Commit** `git commit -m "docs(10): first measured performance baseline (PERFORMANCE.md)"`

---

### Task 9: `osiris-stack` — seeded server for the Console

**Files:**
- Modify: `crates/osiris-real-linux-tests/src/seed.rs`
- Create: `crates/osiris-real-linux-tests/src/bin/osiris-stack.rs`

**Interfaces:**
- Produces: `seed::scenario_lines(base_ts_ns: u64) -> Vec<String>` (NDJSON `CanonicalEvent` lines for all seven generator scenarios, offset 10 s apart); binary `osiris-stack --out <file.json> [--port 8080]` that writes `{"base_url": "...", "username": "admin", "password": "..."}` once seeded and runs until killed (or stdin EOF).

- [ ] **Step 1: Failing test** (`seed.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scenario_contributes_parseable_events() {
        let lines = scenario_lines(1_700_000_000_000_000_000);
        assert!(lines.len() >= 7 * 3);
        for l in &lines {
            let ev: osiris_schema::CanonicalEvent = serde_json::from_str(l).unwrap();
            assert!(ev.timestamp >= 1_700_000_000_000_000_000);
        }
        let all = lines.join("\n");
        assert!(all.contains(osiris_generator::WEB_SHELL_FINAL_PATH));
        assert!(all.contains(osiris_generator::BACKDOOR_UNIT_NAME));
    }
}
```

Run `cargo test -p osiris-real-linux-tests seed` → FAIL.

- [ ] **Step 2: Implement `seed.rs`**

```rust
//! Generator scenarios rendered as server spool lines (what an Agent would
//! have shipped), for seeding a Console stack.
use osiris_generator::{
    container_deploy_in_remote_session_scenario, exec_chain_scenario, network_beacon_scenario,
    network_download_then_write_scenario, persistence_via_systemd_service_scenario,
    ssh_sudo_escalation_scenario, web_shell_drop_scenario,
};
use osiris_schema::HostRef;

pub fn scenario_lines(base_ts_ns: u64) -> Vec<String> {
    let host = HostRef {
        host_id: uuid::Uuid::new_v4(),
        hostname: "seeded-host".into(),
        distro: "Seeded Linux".into(),
        kernel_version: "6.0.0-seed".into(),
        cloud: None,
    };
    let mut pipeline = osiris_pipeline::Pipeline::new(host, "seed-boot".into());
    let scenarios: [fn(u64) -> Vec<osiris_sensor_api::RawEvent>; 7] = [
        exec_chain_scenario,
        web_shell_drop_scenario,
        network_beacon_scenario,
        network_download_then_write_scenario,
        ssh_sudo_escalation_scenario,
        persistence_via_systemd_service_scenario,
        container_deploy_in_remote_session_scenario,
    ];
    let mut out = vec![];
    for (i, s) in scenarios.iter().enumerate() {
        for raw in s(base_ts_ns + i as u64 * 10_000_000_000) {
            out.push(serde_json::to_string(&pipeline.process(raw).event).unwrap());
        }
    }
    out
}
```

Add `osiris-sensor-api = { path = "../osiris-sensor-api" }` to the crate's `[dependencies]`. Run → PASS.

- [ ] **Step 3: `src/bin/osiris-stack.rs`**

```rust
//! Seeded osiris-server for the Console Playwright suite. Writes connection
//! details to --out once data is queryable; exits when stdin closes.
use std::io::{Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use osiris_real_linux_tests::{seed, stack::{Stack, StackOptions}};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let out = arg("--out").expect("--out <file.json>");
    let port: u16 = arg("--port").map(|p| p.parse().unwrap()).unwrap_or(8080);

    let stack = Stack::start(StackOptions { api_port: Some(port), dev_cors: true, ..Default::default() });
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    // Scenarios end ~70 s after base; start them 10 min ago so default time
    // ranges in the Console include them.
    let lines = seed::scenario_lines(now - 600_000_000_000);
    let mut spool = std::fs::OpenOptions::new().create(true).append(true).open(stack.spool_path()).unwrap();
    spool.write_all((lines.join("\n") + "\n").as_bytes()).unwrap();
    stack.wait_for("/api/v1/alerts", Duration::from_secs(60), |v| {
        v.as_array().is_some_and(|a| !a.is_empty())
    });
    std::fs::write(&out, serde_json::json!({
        "base_url": stack.base_url(), "username": "admin", "password": stack.admin_password(),
    }).to_string()).unwrap();
    eprintln!("osiris-stack ready on {}", stack.base_url());
    let _ = std::io::stdin().read_to_end(&mut Vec::new());
}
```

- [ ] **Step 4: Smoke (Windows)** `cargo build --release -p osiris-server -p osiris-real-linux-tests --bin osiris-stack` then run `target/release/osiris-stack --out %TEMP%/stack.json` in the background, confirm the JSON appears and `curl` with a login works, then close stdin/kill.

- [ ] **Step 5: Commit** `git commit -m "feat(10): osiris-stack seeded server for Console browser tests"`

---

### Task 10: Playwright suite

**Files:**
- Modify: `console/package.json` (devDependency `@playwright/test` pinned to the current 1.x release, script `"e2e": "playwright test"`), `console/.gitignore` or root `.gitignore` (`console/test-results/`, `console/playwright-report/`, `console/e2e/.stack.json`), `console/tsconfig.json` (exclude `e2e` if `tsc -b` picks it up; give e2e its own `console/e2e/tsconfig.json`), `console/.eslintrc*` (ensure e2e linted or ignored consistently).
- Create: `console/playwright.config.ts`, `console/e2e/global-setup.ts`, `console/e2e/global-teardown.ts`, `console/e2e/fixtures.ts`, `console/e2e/screens.spec.ts`

**Interfaces:**
- Consumes: Task 9 `osiris-stack --out <file> --port 8080`.

- [ ] **Step 1: Install** `cd console && npm i -D @playwright/test && npx playwright install chromium`.

- [ ] **Step 2: Config**

`console/playwright.config.ts`:

```ts
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  retries: 0,
  workers: 1,
  reporter: [["list"], ["html", { open: "never" }]],
  globalSetup: "./e2e/global-setup.ts",
  globalTeardown: "./e2e/global-teardown.ts",
  use: { baseURL: "http://127.0.0.1:4173", screenshot: "on", trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
  webServer: {
    command: "npm run build && npx vite preview --port 4173 --strictPort",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: false,
    timeout: 180_000,
  },
});
```

(`vite preview` reuses `server.proxy` for `/api` → `127.0.0.1:8080`, where `osiris-stack` listens.)

`console/e2e/global-setup.ts`:

```ts
import { spawn } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import path from "node:path";

export const STACK_FILE = path.join(__dirname, ".stack.json");

export default async function globalSetup() {
  rmSync(STACK_FILE, { force: true });
  const repo = path.resolve(__dirname, "../..");
  const exe = process.platform === "win32" ? "osiris-stack.exe" : "osiris-stack";
  const bin = path.join(process.env.OSIRIS_BIN_DIR ?? path.join(repo, "target", "release"), exe);
  if (!existsSync(bin)) {
    throw new Error(`${bin} missing: cargo build --release -p osiris-server -p osiris-real-linux-tests --bin osiris-stack`);
  }
  const child = spawn(bin, ["--out", STACK_FILE, "--port", "8080"], {
    cwd: repo,
    stdio: ["pipe", "inherit", "inherit"],
  });
  (globalThis as { __osirisStack?: typeof child }).__osirisStack = child;
  const deadline = Date.now() + 90_000;
  while (!existsSync(STACK_FILE)) {
    if (child.exitCode !== null) throw new Error(`osiris-stack exited (${child.exitCode})`);
    if (Date.now() > deadline) throw new Error("osiris-stack not ready in 90s");
    await new Promise((r) => setTimeout(r, 250));
  }
  process.env.OSIRIS_STACK_PID = String(child.pid);
}
```

`console/e2e/global-teardown.ts`:

```ts
export default async function globalTeardown() {
  const pid = Number(process.env.OSIRIS_STACK_PID);
  if (pid) {
    try {
      process.kill(pid);
    } catch {
      /* already gone */
    }
  }
}
```

- [ ] **Step 3: Fixture — login once, collect errors**

`console/e2e/fixtures.ts`:

```ts
import { test as base, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { STACK_FILE } from "./global-setup";

type Problems = { consoleErrors: string[]; failedRequests: string[] };

export const test = base.extend<{ problems: Problems; loggedIn: Page }>({
  problems: async ({ page }, use) => {
    const p: Problems = { consoleErrors: [], failedRequests: [] };
    page.on("console", (m) => m.type() === "error" && p.consoleErrors.push(m.text()));
    page.on("pageerror", (e) => p.consoleErrors.push(String(e)));
    page.on("requestfailed", (r) => p.failedRequests.push(`${r.method()} ${r.url()} ${r.failure()?.errorText}`));
    page.on("response", (r) => r.status() >= 400 && p.failedRequests.push(`${r.status()} ${r.url()}`));
    await use(p);
    expect(p.consoleErrors, "console errors").toEqual([]);
    expect(p.failedRequests, "failed requests").toEqual([]);
  },
  loggedIn: async ({ page, problems }, use) => {
    void problems;
    const { username, password } = JSON.parse(readFileSync(STACK_FILE, "utf8"));
    await page.goto("/login");
    await page.getByLabel("Username").fill(username);
    await page.getByLabel("Password").fill(password);
    await page.getByRole("button", { name: "Log in" }).click();
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    await use(page);
  },
});
export { expect };
```

- [ ] **Step 4: Screen specs** — `console/e2e/screens.spec.ts`. `seeded` = a text that must appear because the seed produces it (data screens); `null` = empty state is legitimate (no AGENT_HEALTH in the seed):

```ts
import { test, expect } from "./fixtures";

const SCREENS: { path: string; heading: RegExp; seeded: RegExp | null }[] = [
  { path: "/", heading: /Overview/, seeded: null },
  { path: "/live-events", heading: /Live Events/, seeded: null },
  { path: "/processes", heading: /Process/, seeded: /bash|curl|sshd/ },
  { path: "/files", heading: /File/, seeded: /\/var\/www\// },
  { path: "/network", heading: /Network/, seeded: /\d+\.\d+\.\d+\.\d+/ },
  { path: "/containers", heading: /Container/, seeded: /[0-9a-f]{12}/ },
  { path: "/hosts", heading: /Hosts/, seeded: null },
  { path: "/groups", heading: /Groups/, seeded: null },
  { path: "/timeline", heading: /Timeline/, seeded: null },
  { path: "/alerts", heading: /Alerts/, seeded: /shell_wrote_file_to_web_root|HIGH/ },
  { path: "/incidents", heading: /Incidents/, seeded: null },
  { path: "/hunting", heading: /Hunting/, seeded: null },
  { path: "/graph", heading: /Graph/, seeded: null },
  { path: "/evidence", heading: /Evidence/, seeded: null },
  { path: "/sensors", heading: /Sensors/, seeded: null },
];

for (const s of SCREENS) {
  test(`${s.path} renders without errors`, async ({ loggedIn: page }, info) => {
    await page.goto(s.path);
    await expect(page.getByRole("heading", { level: 1, name: s.heading })).toBeVisible();
    if (s.seeded) await expect(page.getByText(s.seeded).first()).toBeVisible({ timeout: 15_000 });
    await page.waitForLoadState("networkidle");
    await info.attach("screen", { body: await page.screenshot({ fullPage: true }), contentType: "image/png" });
  });
}

test("process detail opens from the list", async ({ loggedIn: page }) => {
  await page.goto("/processes");
  await page.getByRole("link").filter({ hasText: /bash|curl|sshd/ }).first().click();
  await expect(page).toHaveURL(/\/processes\/.+/);
  await page.waitForLoadState("networkidle");
});

test("a group can be created and its policy editor opens", async ({ loggedIn: page }) => {
  await page.goto("/groups");
  // Use the Groups screen's own create control (read console/src/screens/groups for its label).
  await page.getByRole("button", { name: /new group|create/i }).click();
  await page.getByLabel(/name/i).fill(`e2e-${Date.now()}`);
  await page.getByRole("button", { name: /create|save/i }).click();
  await page.getByRole("link", { name: /e2e-/ }).first().click();
  await expect(page.getByRole("heading", { name: /policy/i })).toBeVisible();
});
```

Before running, open each screen's component under `console/src/screens/<x>/` and correct the heading regex / seeded text / group-creation labels to what the screen actually renders — the table above is the starting hypothesis, the source is the authority. Selectors use roles/labels, never CSS classes.

- [ ] **Step 5: Run** `npm run e2e` (Windows, after building the Rust binaries). Failures are either a wrong selector (fix the spec) or a real Console/API bug (fix the code with a Vitest regression test in `console/src/**`, or a Rust test if API-side). Note each real bug for Task 11's report.

- [ ] **Step 6: Gates** `npm run lint && npm test && npm run build` still pass (Vitest must not collect `e2e/`; set `test.exclude: ["e2e/**", "node_modules/**"]` in `vite.config.ts` if it does).

- [ ] **Step 7: Commit** `git commit -m "test(10): Playwright smoke suite for every Console screen"`

---

### Task 11: Visual pass

**Files:** `docs/VALIDATION.md` (§Console), plus fixes.

- [ ] **Step 1:** Start `osiris-stack` and `vite preview` as in Task 10; with the Playwright MCP browser, visit every screen at 1440×900 and 390×844, take screenshots, and try the primary interaction of each (filter, open detail, change time range, open graph node, run a saved hunt, edit a group policy).
- [ ] **Step 2:** Classify each observation: **bug** (crash, wrong/missing data, broken interaction, unreadable at desktop width) → fix with a regression test (Vitest or Playwright) and commit `fix(10): console: <what>`; **cosmetic/UX** (narrow-width layout, spacing, copy) → list under `docs/VALIDATION.md` §Console as Phase 13 UX debt.
- [ ] **Step 3:** Commit the §Console section: `docs(10): console visual pass findings`.

---

### Task 12: Roadmap and final gates

**Files:** `docs/ROADMAP-REMAINING.md`

- [ ] **Step 1:** Mark Fase 10 done (one paragraph: harness, distros validated, findings fixed, PERFORMANCE.md, Playwright, links to `docs/VALIDATION.md` and `PERFORMANCE.md`); add debts: container/k8s real scenarios (needs Docker/kind), RHEL-like, real DNS capture (Phase 11), CI jobs for real-Linux + Playwright, any Task 4/5/11 deferred items.
- [ ] **Step 2:** Run every gate from Global Constraint #9 on Windows, plus `tools/real-linux/run.sh` once more on Ubuntu (green or documented deferred).
- [ ] **Step 3: Commit** `git commit -m "docs(10): Phase 10 complete in the roadmap"`
