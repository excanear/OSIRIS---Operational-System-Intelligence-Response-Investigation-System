//! Real mutual-TLS loopback tests for the Agent→Server transport.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use osiris_schema::{
    CanonicalEvent, Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION,
};
use osiris_transport::client::{offset_path, run_forwarder, ForwarderConfig};
use osiris_transport::pki::{generate_ca, issue_agent, issue_server, write_issued};
use osiris_transport::server::{BatchHandler, Listener};
use osiris_transport::tls;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn event(host: Uuid, n: u64) -> CanonicalEvent {
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host,
        boot_id: "b".to_string(),
        timestamp: 1_000 + n,
        monotonic_timestamp: 1_000 + n,
        event_type: EventType::ProcessExec,
        category: Category::Process,
        severity: Severity::Info,
        host: HostRef {
            host_id: host,
            hostname: "h".to_string(),
            distro: "d".to_string(),
            kernel_version: "k".to_string(),
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
        provider: "test".to_string(),
        raw_event: None,
        relationships: vec![],
        tags: vec![],
        risk: None,
        event_data: serde_json::json!({}),
    }
}

#[derive(Default)]
struct Recorder {
    received: Mutex<Vec<CanonicalEvent>>,
    /// Fail this many calls before succeeding.
    fail_first: AtomicUsize,
    calls: AtomicUsize,
}

#[async_trait]
impl BatchHandler for Recorder {
    async fn handle(&self, _host: Uuid, events: Vec<CanonicalEvent>) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self
            .fail_first
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err("simulated storage failure".to_string());
        }
        self.received.lock().unwrap().extend(events);
        Ok(())
    }
}

struct Pki {
    dir: tempfile::TempDir,
}

impl Pki {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca = generate_ca("test-ca").unwrap();
        write_issued(dir.path(), "ca", &ca).unwrap();
        let server = issue_server(&ca.cert_pem, &ca.key_pem, &["localhost".into(), "127.0.0.1".into()]).unwrap();
        write_issued(dir.path(), "server", &server).unwrap();
        Self { dir }
    }
    fn p(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn agent(&self, name: &str, host: Uuid) {
        let ca_cert = std::fs::read_to_string(self.p("ca.pem")).unwrap();
        let ca_key = std::fs::read_to_string(self.p("ca.key")).unwrap();
        let issued = issue_agent(&ca_cert, &ca_key, host).unwrap();
        write_issued(self.dir.path(), name, &issued).unwrap();
    }
}

async fn start_server(pki: &Pki, handler: Arc<Recorder>, revoked: HashSet<Uuid>) -> (String, CancellationToken) {
    let cfg = tls::server_config(&pki.p("server.pem"), &pki.p("server.key"), &pki.p("ca.pem")).unwrap();
    let listener = Listener::bind("127.0.0.1:0", cfg, revoked).await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let cancel = CancellationToken::new();
    tokio::spawn(listener.run(handler, cancel.clone()));
    (addr, cancel)
}

fn write_spool(path: &Path, events: &[CanonicalEvent]) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).unwrap();
    for e in events {
        writeln!(f, "{}", serde_json::to_string(e).unwrap()).unwrap();
    }
}

fn forwarder(pki: &Pki, addr: &str, agent: &str, spool: &Path) -> ForwarderConfig {
    let mut cfg = ForwarderConfig::new(
        addr,
        "localhost",
        pki.p("ca.pem"),
        pki.p(&format!("{agent}.pem")),
        pki.p(&format!("{agent}.key")),
        spool,
    );
    cfg.ack_timeout = Duration::from_secs(5);
    cfg
}

async fn wait_for(mut cond: impl FnMut() -> bool) {
    for _ in 0..150 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not reached in time");
}

#[tokio::test]
async fn an_enrolled_agents_spool_is_delivered_and_the_offset_persisted() {
    let pki = Pki::new();
    let host = Uuid::new_v4();
    pki.agent("agent", host);
    let handler = Arc::new(Recorder::default());
    let (addr, server_cancel) = start_server(&pki, handler.clone(), HashSet::new()).await;

    let spool = pki.p("spool.ndjson");
    write_spool(&spool, &[event(host, 1), event(host, 2), event(host, 3)]);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(run_forwarder(forwarder(&pki, &addr, "agent", &spool), cancel.clone()));

    wait_for(|| handler.received.lock().unwrap().len() == 3).await;
    let len = std::fs::metadata(&spool).unwrap().len();
    wait_for(|| std::fs::read_to_string(offset_path(&spool)).ok().and_then(|s| s.parse::<u64>().ok()) == Some(len)).await;

    cancel.cancel();
    task.await.unwrap().unwrap();
    server_cancel.cancel();
}

#[tokio::test]
async fn a_restarted_forwarder_resumes_from_the_acknowledged_offset() {
    let pki = Pki::new();
    let host = Uuid::new_v4();
    pki.agent("agent", host);
    let handler = Arc::new(Recorder::default());
    let (addr, server_cancel) = start_server(&pki, handler.clone(), HashSet::new()).await;
    let spool = pki.p("spool.ndjson");

    write_spool(&spool, &[event(host, 1), event(host, 2)]);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(run_forwarder(forwarder(&pki, &addr, "agent", &spool), cancel.clone()));
    wait_for(|| handler.received.lock().unwrap().len() == 2).await;
    let len = std::fs::metadata(&spool).unwrap().len();
    wait_for(|| std::fs::read_to_string(offset_path(&spool)).ok().and_then(|s| s.parse::<u64>().ok()) == Some(len)).await;
    cancel.cancel();
    task.await.unwrap().unwrap();

    // A new process: only the new event may be sent.
    write_spool(&spool, &[event(host, 3)]);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(run_forwarder(forwarder(&pki, &addr, "agent", &spool), cancel.clone()));
    wait_for(|| handler.received.lock().unwrap().len() == 3).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(handler.received.lock().unwrap().len(), 3, "nothing may be redelivered");
    cancel.cancel();
    task.await.unwrap().unwrap();
    server_cancel.cancel();
}

#[tokio::test]
async fn a_failed_batch_is_retried_and_eventually_delivered() {
    let pki = Pki::new();
    let host = Uuid::new_v4();
    pki.agent("agent", host);
    let handler = Arc::new(Recorder::default());
    handler.fail_first.store(1, Ordering::SeqCst);
    let (addr, server_cancel) = start_server(&pki, handler.clone(), HashSet::new()).await;
    let spool = pki.p("spool.ndjson");
    write_spool(&spool, &[event(host, 1)]);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(run_forwarder(forwarder(&pki, &addr, "agent", &spool), cancel.clone()));

    wait_for(|| handler.received.lock().unwrap().len() == 1).await;
    assert!(handler.calls.load(Ordering::SeqCst) >= 2, "the first attempt failed");
    cancel.cancel();
    task.await.unwrap().unwrap();
    server_cancel.cancel();
}

#[tokio::test]
async fn events_claiming_another_host_are_rejected_and_skipped() {
    let pki = Pki::new();
    let host = Uuid::new_v4();
    pki.agent("agent", host);
    let handler = Arc::new(Recorder::default());
    let (addr, server_cancel) = start_server(&pki, handler.clone(), HashSet::new()).await;
    let spool = pki.p("spool.ndjson");
    write_spool(&spool, &[event(Uuid::new_v4(), 1)]); // a different host id
    let cancel = CancellationToken::new();
    let task = tokio::spawn(run_forwarder(forwarder(&pki, &addr, "agent", &spool), cancel.clone()));

    let len = std::fs::metadata(&spool).unwrap().len();
    wait_for(|| std::fs::read_to_string(offset_path(&spool)).ok().and_then(|s| s.parse::<u64>().ok()) == Some(len)).await;
    assert_eq!(handler.calls.load(Ordering::SeqCst), 0, "the handler must never see a spoofed batch");
    assert!(handler.received.lock().unwrap().is_empty());
    cancel.cancel();
    task.await.unwrap().unwrap();
    server_cancel.cancel();
}

#[tokio::test]
async fn a_revoked_host_is_refused() {
    let pki = Pki::new();
    let host = Uuid::new_v4();
    pki.agent("agent", host);
    let handler = Arc::new(Recorder::default());
    let (addr, server_cancel) = start_server(&pki, handler.clone(), HashSet::from([host])).await;
    let spool = pki.p("spool.ndjson");
    write_spool(&spool, &[event(host, 1)]);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(run_forwarder(forwarder(&pki, &addr, "agent", &spool), cancel.clone()));

    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
    assert!(std::fs::read_to_string(offset_path(&spool)).is_err(), "nothing acknowledged");
    cancel.cancel();
    task.await.unwrap().unwrap();
    server_cancel.cancel();
}

#[tokio::test]
async fn a_certificate_from_a_foreign_ca_is_refused() {
    let pki = Pki::new();
    let host = Uuid::new_v4();
    // An agent certificate issued by a DIFFERENT CA.
    let rogue = generate_ca("rogue-ca").unwrap();
    let issued = issue_agent(&rogue.cert_pem, &rogue.key_pem, host).unwrap();
    write_issued(pki.dir.path(), "rogue", &issued).unwrap();

    let handler = Arc::new(Recorder::default());
    let (addr, server_cancel) = start_server(&pki, handler.clone(), HashSet::new()).await;
    let spool = pki.p("spool.ndjson");
    write_spool(&spool, &[event(host, 1)]);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(run_forwarder(forwarder(&pki, &addr, "rogue", &spool), cancel.clone()));

    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
    cancel.cancel();
    task.await.unwrap().unwrap();
    server_cancel.cancel();
}

#[tokio::test]
async fn a_client_with_no_certificate_cannot_send_anything() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let pki = Pki::new();
    let handler = Arc::new(Recorder::default());
    let (addr, server_cancel) = start_server(&pki, handler.clone(), HashSet::new()).await;

    // A TLS client that trusts the CA but presents NO client certificate.
    let mut roots = rustls::RootCertStore::empty();
    for c in tls::load_certs(&pki.p("ca.pem")).unwrap() {
        roots.add(c).unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    // In TLS 1.3 the client may finish its handshake before the server rejects the
    // missing certificate, so the failure can surface on the first read/write.
    let outcome = async {
        let mut conn = connector.connect(name, tcp).await?;
        conn.write_all(&[0, 0, 0, 1, 0]).await?;
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).await?;
        Ok::<usize, std::io::Error>(n)
    }
    .await;
    assert!(matches!(outcome, Err(_) | Ok(0)), "server must not talk to an unauthenticated client");
    assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
    server_cancel.cancel();
}
