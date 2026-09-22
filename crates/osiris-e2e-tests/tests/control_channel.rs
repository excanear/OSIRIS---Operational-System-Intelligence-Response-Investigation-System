//! End-to-end tests of the Phase 9c-1 command channel: a real authenticated
//! HTTP router -> HubDispatcher -> real mTLS ControlListener -> in-process
//! agent control client (AgentCommandHandler over a recording FakeExecutor).
//! No OS-level action is ever performed.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use osiris_agent::control::AgentCommandHandler;
use osiris_api::{auth_gate, build_auth_router, build_response_router, AuthState, ResponseState};
use osiris_audit::{AuditLog, FileAuditLog};
use osiris_auth::{SqliteUserStore, UserStore};
use osiris_command::keys::generate_signing_key;
use osiris_command::{
    sign, ActionExecutor, Command, CommandAction, CommandResult, ExecDetail, ExecFailure,
    FakeExecutor, Guard, ProtectedTargets, Refusal, ReplayStore, SigningKey,
};
use osiris_schema::{
    CanonicalEvent, Category, EventType, FileRef, HostRef, ProcessKey, ProcessRef, Severity,
    Source, SCHEMA_VERSION,
};
use osiris_server::control::HubDispatcher;
use osiris_storage::Storage;
use osiris_storage_sqlite::SqliteStorage;
use osiris_transport::control::{
    run_control_client, ControlClientConfig, ControlHub, ControlListener,
};
use osiris_transport::pki::{generate_ca, issue_agent, issue_server, write_issued};
use osiris_transport::tls;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Wraps a `FakeExecutor` and gives quarantine a fixed vault id, so restore can
/// be driven from the first response.
struct Exec {
    inner: Arc<FakeExecutor>,
    qid: Uuid,
}

impl ActionExecutor for Exec {
    fn terminate(
        &self,
        pid: u32,
        exe: &str,
        at: u64,
        dry: bool,
    ) -> Result<ExecDetail, ExecFailure> {
        self.inner.terminate(pid, exe, at, dry)
    }
    fn quarantine(
        &self,
        path: &str,
        inode: u64,
        dev: u64,
        dry: bool,
    ) -> Result<ExecDetail, ExecFailure> {
        let mut d = self.inner.quarantine(path, inode, dev, dry)?;
        d.quarantine_id = Some(self.qid);
        Ok(d)
    }
    fn restore(&self, id: Uuid, dry: bool) -> Result<ExecDetail, ExecFailure> {
        self.inner.restore(id, dry)
    }
}

fn mint_admin_session(dir: &std::path::Path) -> (AuthState, String) {
    let (user_store, _bootstrap) = SqliteUserStore::open(dir.join("users.db")).unwrap();
    let admin = user_store.get_user_by_username("admin").unwrap().unwrap();
    let token = user_store
        .create_session(admin.user_id, 3600)
        .unwrap()
        .token;
    let audit_log: Arc<dyn osiris_audit::AuditLog + Send + Sync> =
        Arc::new(FileAuditLog::open(dir.join("auth-audit.jsonl")).unwrap());
    let state = AuthState {
        users: Arc::new(user_store),
        audit_log,
        session_ttl_seconds: 3600,
        tenants: Arc::new(osiris_tenancy::SqliteTenantStore::open(dir.join("tenants.db")).unwrap()),
    };
    (state, token)
}

fn event(host: Uuid) -> CanonicalEvent {
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host,
        boot_id: "b".into(),
        timestamp: 5000,
        monotonic_timestamp: 5000,
        event_type: EventType::ProcessExec,
        category: Category::Process,
        severity: Severity::Info,
        host: HostRef {
            host_id: host,
            hostname: "h".into(),
            distro: "d".into(),
            kernel_version: "k".into(),
            cloud: None,
        },
        user: None,
        session: None,
        process: None,
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
        provider: "test".into(),
        raw_event: None,
        relationships: vec![],
        tags: vec![],
        risk: None,
        event_data: serde_json::json!({}),
    }
}

struct Harness {
    dir: tempfile::TempDir,
    base: String,
    token: String,
    host: Uuid,
    qid: Uuid,
    fake: Arc<FakeExecutor>,
    hub: ControlHub,
    proc_key: ProcessKey,
    cancel: CancellationToken,
    client: reqwest::Client,
}

impl Harness {
    /// `server_key` signs what the API sends; the agent trusts `agent_key`.
    /// `connect` false leaves the agent offline.
    async fn start(server_key: SigningKey, agent_key: SigningKey, connect: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let host = Uuid::new_v4();
        let qid = Uuid::new_v4();
        let cancel = CancellationToken::new();

        // PKI.
        let pki = dir.path().join("pki");
        std::fs::create_dir_all(&pki).unwrap();
        let ca = generate_ca("e2e-ca").unwrap();
        write_issued(&pki, "ca", &ca).unwrap();
        let server = issue_server(
            &ca.cert_pem,
            &ca.key_pem,
            &["localhost".into(), "127.0.0.1".into()],
        )
        .unwrap();
        write_issued(&pki, "server", &server).unwrap();
        let agent = issue_agent(&ca.cert_pem, &ca.key_pem, host).unwrap();
        write_issued(&pki, "agent", &agent).unwrap();

        // Control listener + hub.
        let hub = ControlHub::new();
        let tls_cfg = tls::server_config(
            &pki.join("server.pem"),
            &pki.join("server.key"),
            &pki.join("ca.pem"),
        )
        .unwrap();
        let listener = ControlListener::bind("127.0.0.1:0", tls_cfg, HashSet::new(), hub.clone())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(listener.run(cancel.clone()));

        // Agent: real handler + guard over the recording fake executor.
        let fake = Arc::new(FakeExecutor::default());
        let guard = Guard {
            host_id: host,
            key: agent_key.verifying_key(),
            replay: ReplayStore::open(&dir.path().join("seen")).unwrap(),
            protected: ProtectedTargets {
                agent_pid: 500,
                extra_pids: vec![],
                vault: dir.path().join("vault"),
            },
        };
        let handler = Arc::new(AgentCommandHandler::new(
            guard,
            Arc::new(Exec {
                inner: fake.clone(),
                qid,
            }),
        ));
        if connect {
            let cfg = ControlClientConfig {
                server_addr: addr,
                server_name: "localhost".into(),
                ca: pki.join("ca.pem"),
                cert: pki.join("agent.pem"),
                key: pki.join("agent.key"),
            };
            let c = cancel.clone();
            tokio::spawn(async move {
                run_control_client(cfg, handler, c).await.unwrap();
            });
            for _ in 0..100 {
                if hub.connected(host) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(hub.connected(host), "agent never connected");
        }

        // Storage with a process event and a file event for the host.
        let storage: Arc<dyn Storage> =
            Arc::new(SqliteStorage::open(dir.path().join("events.db")).unwrap());
        let proc_key = ProcessKey::new(host, "b", 42, 5);
        let mut pe = event(host);
        pe.process = Some(ProcessRef {
            process_key: proc_key,
            pid: 42,
            exe_path: "/bin/evil".into(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 5,
        });
        storage.write(&pe).unwrap();
        let mut fe = event(host);
        fe.timestamp = 6000;
        fe.event_type = EventType::FileWrite;
        fe.category = Category::File;
        fe.file = Some(FileRef {
            path: "/tmp/mal".into(),
            previous_path: None,
            inode: Some(11),
            device_id: Some(7),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        storage.write(&fe).unwrap();

        // Real authenticated router.
        let state = ResponseState {
            commands: Arc::new(HubDispatcher::new(
                hub.clone(),
                server_key,
                Duration::from_secs(10),
            )),
            storage,
            evidence: Arc::new(
                osiris_evidence::SqliteEvidenceStore::open(
                    dir.path().join("evidence.db").to_str().unwrap(),
                )
                .unwrap(),
            ),
            links: Arc::new(
                osiris_evidence::SqliteEvidenceIncidentLinks::open(
                    dir.path().join("links.db").to_str().unwrap(),
                )
                .unwrap(),
            ),
            incidents: Arc::new(
                osiris_evidence::SqliteIncidentStore::open(dir.path().join("incidents.db"))
                    .unwrap(),
            ),
            audit_log: Arc::new(
                FileAuditLog::open(dir.path().join("response-audit.jsonl")).unwrap(),
            ),
        };
        let (auth_state, token) = mint_admin_session(dir.path());
        let app = build_response_router(state)
            .merge(build_auth_router(auth_state.clone()))
            .layer(axum::middleware::from_fn_with_state(auth_state, auth_gate));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

        Self {
            dir,
            base,
            token,
            host,
            qid,
            fake,
            hub,
            proc_key,
            cancel,
            client: reqwest::Client::new(),
        }
    }

    async fn post(&self, action: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
        let r = self
            .client
            .post(format!("{}/api/v1/response/{action}", self.base))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        let text = r.text().await.unwrap();
        let v = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
        (status, v)
    }

    fn proc_body(&self) -> serde_json::Value {
        serde_json::json!({
            "target": {"kind": "PROCESS", "process_key": self.proc_key},
            "reason": "contain", "dry_run": false
        })
    }

    fn file_body(&self) -> serde_json::Value {
        serde_json::json!({
            "target": {"kind": "FILE", "host_id": self.host, "inode": 11, "device_id": 7},
            "reason": "contain", "dry_run": false
        })
    }

    fn audit_count(&self) -> usize {
        FileAuditLog::open(self.dir.path().join("response-audit.jsonl"))
            .unwrap()
            .read_all()
            .unwrap()
            .len()
    }

    fn calls(&self) -> Vec<String> {
        self.fake.calls.lock().unwrap().clone()
    }

    /// A command validly signed by `key` for this host.
    fn signed(
        &self,
        key: &SigningKey,
        action: CommandAction,
        nonce: u8,
    ) -> osiris_command::SignedCommand {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        sign(
            Command {
                command_id: Uuid::new_v4(),
                host_id: self.host,
                action,
                dry_run: false,
                issued_at_ms: now,
                expires_at_ms: now + 30_000,
                nonce: [nonce; 16],
                actor: "e2e".into(),
                reason: "e2e".into(),
            },
            key,
        )
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn terminate_action() -> CommandAction {
    CommandAction::TerminateProcess {
        pid: 42,
        exe_path: "/bin/evil".into(),
        observed_at_ns: 5000,
    }
}

#[tokio::test]
async fn terminate_happy_path_reaches_the_agent_with_exact_arguments() {
    let k = generate_signing_key();
    let h = Harness::start(k.clone(), k, true).await;
    let (status, body) = h.post("terminate_process", h.proc_body()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["ok"], serde_json::json!(true));
    assert_eq!(
        h.calls(),
        vec!["terminate pid=42 exe=/bin/evil observed_at_ns=5000 dry_run=false".to_string()]
    );
    assert_eq!(h.audit_count(), 2);
}

#[tokio::test]
async fn quarantine_then_restore_with_the_returned_id() {
    let k = generate_signing_key();
    let h = Harness::start(k.clone(), k, true).await;
    let (status, body) = h.post("quarantine_file", h.file_body()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["quarantine_id"], serde_json::json!(h.qid));
    assert_eq!(h.audit_count(), 2);

    let qid = body["quarantine_id"].as_str().unwrap().to_string();
    let (status, body) = h
        .post(
            "restore_file",
            serde_json::json!({
                "quarantine_id": qid, "host_id": h.host,
                "reason": "false positive", "dry_run": false
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        h.calls(),
        vec![
            "quarantine path=/tmp/mal inode=11 device_id=7 dry_run=false".to_string(),
            format!("restore id={} dry_run=false", h.qid),
        ]
    );
    assert_eq!(h.audit_count(), 4);
}

#[tokio::test]
async fn an_agent_that_is_not_connected_yields_409_and_two_audit_entries() {
    let k = generate_signing_key();
    let h = Harness::start(k.clone(), k, false).await;
    let (status, body) = h.post("terminate_process", h.proc_body()).await;
    assert_eq!(status, 409, "{body}");
    assert!(h.calls().is_empty());
    assert_eq!(h.audit_count(), 2);
}

#[tokio::test]
async fn a_replayed_signed_command_is_refused_through_the_hub() {
    let k = generate_signing_key();
    let h = Harness::start(k.clone(), k.clone(), true).await;
    let cmd = h.signed(&k, terminate_action(), 1);
    let first = h
        .hub
        .send(h.host, cmd.clone(), Duration::from_secs(5))
        .await
        .unwrap();
    assert!(matches!(first, CommandResult::Executed { .. }), "{first:?}");
    let second = h
        .hub
        .send(h.host, cmd, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        second,
        CommandResult::Refused {
            reason: Refusal::Replay
        }
    );
    assert_eq!(h.calls().len(), 1);
}

#[tokio::test]
async fn a_command_signed_by_a_different_key_is_refused_and_touches_nothing() {
    let (trusted, rogue) = (generate_signing_key(), generate_signing_key());
    let h = Harness::start(trusted.clone(), trusted, true).await;
    let cmd = h.signed(&rogue, terminate_action(), 2);
    let r = h
        .hub
        .send(h.host, cmd, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        r,
        CommandResult::Refused {
            reason: Refusal::BadSignature
        }
    );
    assert!(h.calls().is_empty());
}

#[tokio::test]
async fn a_server_signing_with_the_wrong_key_is_422_via_the_api_with_two_audit_entries() {
    let (server_key, agent_trusts) = (generate_signing_key(), generate_signing_key());
    let h = Harness::start(server_key, agent_trusts, true).await;
    let (status, body) = h.post("terminate_process", h.proc_body()).await;
    assert_eq!(status, 422, "{body}");
    assert!(h.calls().is_empty());
    assert_eq!(h.audit_count(), 2);
}
