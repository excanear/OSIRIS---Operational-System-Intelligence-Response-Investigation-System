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
        let dir = tempfile::Builder::new()
            .prefix("osiris-p10-")
            .tempdir()
            .unwrap();
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

        let server = spawn(
            &bin_path("osiris-server"),
            &d.join("server.yaml"),
            &d.join("server.log"),
        );
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
            || {
                format!(
                    "--- server.log ---\n{}",
                    tail(&logs_dir.join("server.log"), 60)
                )
            },
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
            // Owned by the Stack before the wait so a panic there still reaps it in Drop.
            stack.agent = Some(spawn(
                &bin_path("osiris-agent"),
                &d.join("agent.yaml"),
                &d.join("agent.log"),
            ));
            let host = host_id.unwrap().to_string();
            let hosts_url = format!("{}/api/v1/hosts", stack.base_url);
            wait_ready_or_exit(
                stack.agent.as_mut().unwrap(),
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
        }
        stack
    }

    pub fn dir(&self) -> &Path {
        self.dir.path()
    }
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn admin_password(&self) -> &str {
        &self.admin_password
    }
    pub fn host_id(&self) -> Option<Uuid> {
        self.host_id
    }
    pub fn agent_addr(&self) -> String {
        format!("127.0.0.1:{}", self.agent_port)
    }
    pub fn spool_path(&self) -> PathBuf {
        self.dir.path().join("server-spool.ndjson")
    }
    pub fn events_db(&self) -> PathBuf {
        self.dir.path().join("events.db")
    }
    pub fn server_pid(&self) -> u32 {
        self.server.id()
    }
    pub fn agent_pid(&self) -> Option<u32> {
        self.agent.as_ref().map(|c| c.id())
    }

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
                panic!(
                    "{path} never matched within {deadline:?}\nlast body: {s}\n{}",
                    self.logs_tail()
                );
            }
            std::thread::sleep(POLL);
        }
    }
}

fn spawn(bin: &Path, config: &Path, log: &Path) -> Child {
    assert!(
        bin.exists(),
        "{} missing - build with `cargo build --release`",
        bin.display()
    );
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
            let kept = std::mem::replace(&mut self.dir, tempfile::tempdir().unwrap()).keep();
            eprintln!("stack dir kept for post-mortem: {}", kept.display());
        }
    }
}

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
                String::new,
            )
        });
        assert!(err.is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }
}
