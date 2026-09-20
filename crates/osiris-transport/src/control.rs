//! Server-to-Agent control connection (Phase 9c-1): the Agent dials the Server
//! over mTLS and keeps the connection open; the Server pushes signed commands
//! down it and matches the Agent's results by `command_id`.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use osiris_command::{CommandResult, SignedCommand};
use rustls::pki_types::ServerName;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::client::{sleep_or_cancel, Backoff, CONNECT_TIMEOUT};
use crate::frame::{read_frame, write_frame, FrameError};
use crate::server::{
    host_id_from_cert, IpCounter, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT, MAX_CONNECTIONS,
    MAX_CONNECTIONS_PER_IP,
};
use crate::tls::{client_config, TlsError};
use crate::wire::{ControlClientMsg, ControlServerMsg};

/// The Server pings this often; any inbound frame counts as liveness.
const PING_INTERVAL: Duration = Duration::from_secs(30);
/// A single frame write that takes longer than this drops the connection.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Commands queued towards one Agent connection.
const COMMAND_QUEUE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    #[error("host has no control connection")]
    Offline,
    #[error("timed out waiting for the agent's result")]
    TimedOut,
    #[error("the control connection was lost or replaced")]
    Disconnected,
    #[error("a command with this id is already pending")]
    Duplicate,
}

type Reply = Result<CommandResult, SendError>;
type Outbound = (SignedCommand, oneshot::Sender<Reply>);

struct HostConn {
    tx: mpsc::Sender<Outbound>,
    id: u64,
    /// Cancelled when a newer connection for the host replaces this one.
    replaced: CancellationToken,
}

#[derive(Default)]
struct HubState {
    conns: HashMap<Uuid, HostConn>,
    next_id: u64,
}

/// Registry of live control connections, one per host. Cheap to clone.
#[derive(Clone, Default)]
pub struct ControlHub {
    state: Arc<Mutex<HubState>>,
}

impl ControlHub {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HubState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn connected(&self, host: Uuid) -> bool {
        self.lock()
            .conns
            .get(&host)
            .is_some_and(|c| !c.tx.is_closed())
    }

    /// Sends `cmd` to `host` and waits up to `timeout` for its result. Never queues
    /// for an offline host.
    pub async fn send(
        &self,
        host: Uuid,
        cmd: SignedCommand,
        timeout: Duration,
    ) -> Result<CommandResult, SendError> {
        // Clone the sender out so no lock is held across an await.
        let tx = self
            .lock()
            .conns
            .get(&host)
            .map(|c| c.tx.clone())
            .ok_or(SendError::Offline)?;
        let (result_tx, result_rx) = oneshot::channel();
        let exchange = async {
            tx.send((cmd, result_tx))
                .await
                .map_err(|_| SendError::Disconnected)?;
            // The connection task drops the sender when it ends or is replaced.
            result_rx.await.map_err(|_| SendError::Disconnected)?
        };
        tokio::time::timeout(timeout, exchange)
            .await
            .map_err(|_| SendError::TimedOut)?
    }

    /// Registers a connection, replacing (and thereby closing) any older one.
    fn register(&self, host: Uuid, tx: mpsc::Sender<Outbound>, replaced: CancellationToken) -> u64 {
        let mut st = self.lock();
        st.next_id += 1;
        let id = st.next_id;
        if let Some(old) = st.conns.insert(host, HostConn { tx, id, replaced }) {
            old.replaced.cancel();
        }
        id
    }

    fn unregister(&self, host: Uuid, id: u64) {
        let mut st = self.lock();
        if st.conns.get(&host).is_some_and(|c| c.id == id) {
            st.conns.remove(&host);
        }
    }
}

pub struct ControlListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    revoked: Arc<HashSet<Uuid>>,
    hub: ControlHub,
}

impl ControlListener {
    pub async fn bind(
        addr: &str,
        tls: Arc<rustls::ServerConfig>,
        revoked: HashSet<Uuid>,
        hub: ControlHub,
    ) -> std::io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
            acceptor: TlsAcceptor::from(tls),
            revoked: Arc::new(revoked),
            hub,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accepts connections until `cancel` fires.
    pub async fn run(self, cancel: CancellationToken) {
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let per_ip = Arc::new(IpCounter::default());
        loop {
            let accepted = tokio::select! {
                r = self.listener.accept() => r,
                _ = cancel.cancelled() => return,
            };
            let (stream, peer) = match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "control listener accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                tracing::warn!(%peer, "control listener at its connection limit; refusing");
                continue;
            };
            let Some(ip_guard) = per_ip.acquire(peer.ip(), MAX_CONNECTIONS_PER_IP) else {
                tracing::warn!(%peer, "too many concurrent control connections from this address; refusing");
                continue;
            };
            let acceptor = self.acceptor.clone();
            let revoked = self.revoked.clone();
            let hub = self.hub.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ip_guard = ip_guard;
                if let Err(reason) = serve(stream, acceptor, revoked, hub, cancel).await {
                    tracing::info!(%peer, %reason, "control connection closed");
                }
            });
        }
    }
}

/// Truncates to 64 characters and replaces control characters with `?`.
fn sanitize_agent_version(v: &str) -> String {
    v.chars()
        .take(64)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// Removes the connection from the hub when the serving task ends (only if it
/// is still the registered one).
struct Registration {
    hub: ControlHub,
    host: Uuid,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.hub.unregister(self.host, self.id);
    }
}

/// Aborts the reader task when the connection task ends.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Reads frames into a channel (a frame read is not cancel-safe, so it cannot
/// sit directly in a `select!`). Each read is bounded by the idle timeout.
fn spawn_reader<R, T>(mut rd: ReadHalf<R>) -> (mpsc::Receiver<Result<T, String>>, AbortOnDrop)
where
    R: tokio::io::AsyncRead + Send + 'static,
    T: serde::de::DeserializeOwned + Send + 'static,
{
    let (tx, rx) = mpsc::channel(8);
    let handle = tokio::spawn(async move {
        loop {
            let item = match tokio::time::timeout(IDLE_TIMEOUT, read_frame::<_, T>(&mut rd)).await {
                Err(_) => Err("idle timeout".to_string()),
                Ok(Err(FrameError::Closed)) => Err("closed by peer".to_string()),
                Ok(Err(e)) => Err(e.to_string()),
                Ok(Ok(msg)) => Ok(msg),
            };
            let stop = item.is_err();
            if tx.send(item).await.is_err() || stop {
                return;
            }
        }
    });
    (rx, AbortOnDrop(handle))
}

async fn write_bounded<W, T>(w: &mut WriteHalf<W>, msg: &T) -> Result<(), String>
where
    W: tokio::io::AsyncWrite,
    T: serde::Serialize,
{
    match tokio::time::timeout(WRITE_TIMEOUT, write_frame(w, msg)).await {
        Err(_) => Err("write timed out".to_string()),
        Ok(r) => r.map_err(|e| e.to_string()),
    }
}

async fn serve(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    revoked: Arc<HashSet<Uuid>>,
    hub: ControlHub,
    cancel: CancellationToken,
) -> Result<(), String> {
    let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .map_err(|_| "tls handshake timed out".to_string())?
        .map_err(|e| format!("tls handshake failed: {e}"))?;

    let host_id = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(host_id_from_cert)
        .ok_or("client certificate carries no osiris host id")?;
    if revoked.contains(&host_id) {
        return Err(format!("host {host_id} is revoked"));
    }

    let (rd, mut wr) = tokio::io::split(tls);
    let (mut inbound, _reader) = spawn_reader::<_, ControlClientMsg>(rd);

    // The Agent must introduce itself promptly.
    let hello = tokio::select! {
        r = tokio::time::timeout(HANDSHAKE_TIMEOUT, inbound.recv()) => r,
        _ = cancel.cancelled() => return Ok(()),
    };
    let agent_version = match hello {
        Ok(Some(Ok(ControlClientMsg::Hello { agent_version }))) => agent_version,
        Ok(Some(Ok(_))) => return Err("first frame was not Hello".to_string()),
        Ok(Some(Err(e))) => return Err(e),
        Ok(None) => return Err("closed before Hello".to_string()),
        Err(_) => return Err("timed out waiting for Hello".to_string()),
    };

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Outbound>(COMMAND_QUEUE);
    let replaced = CancellationToken::new();
    let id = hub.register(host_id, cmd_tx, replaced.clone());
    let _registration = Registration {
        hub: hub.clone(),
        host: host_id,
        id,
    };
    let agent_version = sanitize_agent_version(&agent_version);
    tracing::info!(%host_id, %agent_version, "agent control connection established");
    // Acts as the acceptance ack: the Agent resets its reconnect backoff on it.
    write_bounded(&mut wr, &ControlServerMsg::Ping).await?;

    // Dropping `pending` (on any exit) resolves waiting senders with `Disconnected`.
    let mut pending: HashMap<Uuid, oneshot::Sender<Reply>> = HashMap::new();
    let mut ping =
        tokio::time::interval_at(tokio::time::Instant::now() + PING_INTERVAL, PING_INTERVAL);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            _ = replaced.cancelled() => return Ok(()),
            out = cmd_rx.recv() => {
                let Some((cmd, result_tx)) = out else { return Ok(()) };
                // Never deliver on a connection that is being replaced or shut
                // down: the caller is told `Disconnected` and may retry.
                if replaced.is_cancelled() || cancel.is_cancelled() {
                    return Ok(());
                }
                let command_id = cmd.command.command_id;
                if pending.get(&command_id).is_some_and(|tx| !tx.is_closed()) {
                    let _ = result_tx.send(Err(SendError::Duplicate));
                    continue;
                }
                pending.insert(command_id, result_tx);
                write_bounded(&mut wr, &ControlServerMsg::Command(cmd)).await?;
            }
            msg = inbound.recv() => match msg {
                None => return Ok(()),
                Some(Err(e)) => return Err(e),
                Some(Ok(ControlClientMsg::Result { command_id, result })) => {
                    match pending.remove(&command_id) {
                        Some(tx) => { let _ = tx.send(Ok(result)); }
                        None => tracing::debug!(%host_id, %command_id, "result for an unknown or expired command; ignoring"),
                    }
                }
                Some(Ok(ControlClientMsg::Pong)) => {}
                Some(Ok(ControlClientMsg::Hello { .. })) => {
                    tracing::debug!(%host_id, "duplicate Hello; ignoring");
                }
            },
            _ = ping.tick() => {
                pending.retain(|_, tx| !tx.is_closed());
                write_bounded(&mut wr, &ControlServerMsg::Ping).await?;
            }
        }
    }
}

/// Executes a command on the Agent.
#[async_trait]
pub trait CommandHandler: Send + Sync {
    async fn handle(&self, cmd: SignedCommand) -> CommandResult;
}

#[derive(Debug, Clone)]
pub struct ControlClientConfig {
    pub server_addr: String,
    /// The name the Server's certificate must be valid for.
    pub server_name: String,
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Runs until `cancel` fires. Returns an error only if the TLS material is unusable.
pub async fn run_control_client(
    cfg: ControlClientConfig,
    handler: Arc<dyn CommandHandler>,
    cancel: CancellationToken,
) -> Result<(), TlsError> {
    let tls = client_config(&cfg.ca, &cfg.cert, &cfg.key)?;
    let server_name = ServerName::try_from(cfg.server_name.clone())
        .map_err(|e| TlsError::Rustls(format!("invalid server_name: {e}")))?;
    let connector = TlsConnector::from(tls);
    let mut backoff = Backoff::default();

    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        let stream = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect(&cfg.server_addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            other => {
                let why = match other {
                    Ok(Err(e)) => e.to_string(),
                    _ => "connect timed out".to_string(),
                };
                tracing::warn!(addr = %cfg.server_addr, %why, "control client cannot reach the server");
                if sleep_or_cancel(backoff.next_delay(), &cancel).await {
                    return Ok(());
                }
                continue;
            }
        };
        let conn = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            connector.connect(server_name.clone(), stream),
        )
        .await
        {
            Ok(Ok(c)) => c,
            other => {
                let why = match other {
                    Ok(Err(e)) => e.to_string(),
                    _ => "tls handshake timed out".to_string(),
                };
                tracing::warn!(%why, "control client tls handshake failed");
                if sleep_or_cancel(backoff.next_delay(), &cancel).await {
                    return Ok(());
                }
                continue;
            }
        };
        match control_session(conn, &handler, &cancel, &mut backoff).await {
            Ok(()) => return Ok(()),
            Err(why) => tracing::warn!(%why, "control connection lost; reconnecting"),
        }
        if sleep_or_cancel(backoff.next_delay(), &cancel).await {
            return Ok(());
        }
    }
}

/// One connected session. `Ok` means cancelled; `Err` means reconnect.
async fn control_session<S>(
    conn: S,
    handler: &Arc<dyn CommandHandler>,
    cancel: &CancellationToken,
    backoff: &mut Backoff,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    let (rd, mut wr) = tokio::io::split(conn);
    let (mut inbound, _reader) = spawn_reader::<_, ControlServerMsg>(rd);
    write_bounded(
        &mut wr,
        &ControlClientMsg::Hello {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )
    .await?;
    // Backoff resets only once the Server answers (its first frame), so a
    // rejected agent keeps backing off.
    let mut acknowledged = false;

    let (result_tx, mut results) = mpsc::channel::<ControlClientMsg>(COMMAND_QUEUE);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            msg = inbound.recv() => match msg {
                None => return Err("reader stopped".to_string()),
                Some(Err(e)) => return Err(e),
                Some(Ok(m)) if !acknowledged => {
                    acknowledged = true;
                    backoff.reset();
                    tracing::info!("control connection established");
                    inbound_msg(m, &mut wr, handler, &result_tx).await?;
                }
                Some(Ok(m)) => inbound_msg(m, &mut wr, handler, &result_tx).await?,
            },
            Some(reply) = results.recv() => {
                write_bounded(&mut wr, &reply).await?;
            }
        }
    }
}

async fn inbound_msg<W: tokio::io::AsyncWrite>(
    m: ControlServerMsg,
    wr: &mut WriteHalf<W>,
    handler: &Arc<dyn CommandHandler>,
    result_tx: &mpsc::Sender<ControlClientMsg>,
) -> Result<(), String> {
    match m {
        ControlServerMsg::Ping => write_bounded(wr, &ControlClientMsg::Pong).await,
        ControlServerMsg::Command(cmd) => {
            let command_id = cmd.command.command_id;
            let handler = handler.clone();
            let result_tx = result_tx.clone();
            tokio::spawn(async move {
                let result = handler.handle(cmd).await;
                let _ = result_tx
                    .send(ControlClientMsg::Result { command_id, result })
                    .await;
            });
            Ok(())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::{generate_ca, issue_agent, issue_server, write_issued};
    use crate::tls;
    use osiris_command::{Command, CommandAction};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Pki {
        dir: tempfile::TempDir,
    }

    impl Pki {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let ca = generate_ca("test-ca").unwrap();
            write_issued(dir.path(), "ca", &ca).unwrap();
            let server = issue_server(
                &ca.cert_pem,
                &ca.key_pem,
                &["localhost".into(), "127.0.0.1".into()],
            )
            .unwrap();
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

    /// Sleeps `pid` milliseconds, then reports what it ran.
    #[derive(Default)]
    struct Fake {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl CommandHandler for Fake {
        async fn handle(&self, cmd: SignedCommand) -> CommandResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let CommandAction::TerminateProcess { pid, .. } = cmd.command.action else {
                unreachable!()
            };
            tokio::time::sleep(Duration::from_millis(pid as u64)).await;
            CommandResult::DryRunOk {
                would_do: format!("ran {pid}"),
            }
        }
    }

    fn cmd(host: Uuid, sleep_ms: u32) -> SignedCommand {
        SignedCommand {
            command: Command {
                command_id: Uuid::new_v4(),
                host_id: host,
                action: CommandAction::TerminateProcess {
                    pid: sleep_ms,
                    exe_path: "/bin/x".into(),
                    observed_at_ns: 1,
                },
                dry_run: true,
                issued_at_ms: 0,
                expires_at_ms: u64::MAX,
                nonce: [0; 16],
                actor: "t".into(),
                reason: "t".into(),
            },
            signature: vec![],
        }
    }

    type Started = (
        String,
        ControlHub,
        CancellationToken,
        tokio::task::JoinHandle<()>,
    );

    async fn start(pki: &Pki, revoked: HashSet<Uuid>) -> Started {
        let cfg = tls::server_config(&pki.p("server.pem"), &pki.p("server.key"), &pki.p("ca.pem"))
            .unwrap();
        let hub = ControlHub::new();
        let l = ControlListener::bind("127.0.0.1:0", cfg, revoked, hub.clone())
            .await
            .unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(l.run(cancel.clone()));
        (addr, hub, cancel, task)
    }

    fn client(
        pki: &Pki,
        addr: &str,
        name: &str,
        handler: Arc<Fake>,
    ) -> (CancellationToken, tokio::task::JoinHandle<()>) {
        let cfg = ControlClientConfig {
            server_addr: addr.to_string(),
            server_name: "localhost".into(),
            ca: pki.p("ca.pem"),
            cert: pki.p(&format!("{name}.pem")),
            key: pki.p(&format!("{name}.key")),
        };
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        let task = tokio::spawn(async move {
            run_control_client(cfg, handler, c).await.unwrap();
        });
        (cancel, task)
    }

    async fn wait_connected(hub: &ControlHub, host: Uuid) {
        for _ in 0..100 {
            if hub.connected(host) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("agent never connected");
    }

    #[tokio::test]
    async fn a_command_reaches_the_agent_and_its_result_returns() {
        let pki = Pki::new();
        let host = Uuid::new_v4();
        pki.agent("a", host);
        let (addr, hub, cancel, _t) = start(&pki, HashSet::new()).await;
        let fake = Arc::new(Fake::default());
        let (ccancel, _ct) = client(&pki, &addr, "a", fake.clone());
        wait_connected(&hub, host).await;
        let r = hub
            .send(host, cmd(host, 0), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            r,
            CommandResult::DryRunOk {
                would_do: "ran 0".into()
            }
        );
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        ccancel.cancel();
        cancel.cancel();
    }

    #[tokio::test]
    async fn send_to_an_offline_host_fails_immediately() {
        let hub = ControlHub::new();
        let host = Uuid::new_v4();
        let started = std::time::Instant::now();
        let r = hub.send(host, cmd(host, 0), Duration::from_secs(5)).await;
        assert_eq!(r, Err(SendError::Offline));
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(!hub.connected(host));
    }

    #[tokio::test]
    async fn a_slow_handler_times_out_and_its_late_result_is_ignored() {
        let pki = Pki::new();
        let host = Uuid::new_v4();
        pki.agent("a", host);
        let (addr, hub, cancel, _t) = start(&pki, HashSet::new()).await;
        let (ccancel, _ct) = client(&pki, &addr, "a", Arc::new(Fake::default()));
        wait_connected(&hub, host).await;
        let r = hub
            .send(host, cmd(host, 600), Duration::from_millis(200))
            .await;
        assert_eq!(r, Err(SendError::TimedOut));
        // The late result arrives, is ignored, and the connection stays healthy.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(hub.connected(host));
        let r = hub
            .send(host, cmd(host, 0), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            r,
            CommandResult::DryRunOk {
                would_do: "ran 0".into()
            }
        );
        ccancel.cancel();
        cancel.cancel();
    }

    #[tokio::test]
    async fn a_second_connection_replaces_the_first() {
        let pki = Pki::new();
        let host = Uuid::new_v4();
        pki.agent("a", host);
        pki.agent("b", host);
        let (addr, hub, cancel, _t) = start(&pki, HashSet::new()).await;
        let (acancel, _at) = client(&pki, &addr, "a", Arc::new(Fake::default()));
        wait_connected(&hub, host).await;
        let h2 = hub.clone();
        let pending = tokio::spawn(async move {
            h2.send(host, cmd(host, 30_000), Duration::from_secs(20))
                .await
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        let fake_b = Arc::new(Fake::default());
        let (bcancel, _bt) = client(&pki, &addr, "b", fake_b.clone());
        let r = tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .expect("pending send must resolve")
            .unwrap();
        assert_eq!(r, Err(SendError::Disconnected));
        acancel.cancel();
        // The newer connection serves commands.
        wait_connected(&hub, host).await;
        let r = hub
            .send(host, cmd(host, 0), Duration::from_secs(5))
            .await
            .unwrap();
        assert!(matches!(r, CommandResult::DryRunOk { .. }));
        assert_eq!(fake_b.calls.load(Ordering::SeqCst), 1);
        bcancel.cancel();
        cancel.cancel();
    }

    #[tokio::test]
    async fn a_revoked_host_is_refused() {
        let pki = Pki::new();
        let host = Uuid::new_v4();
        pki.agent("a", host);
        let (addr, hub, cancel, _t) = start(&pki, HashSet::from([host])).await;
        let (ccancel, _ct) = client(&pki, &addr, "a", Arc::new(Fake::default()));
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(!hub.connected(host));
        ccancel.cancel();
        cancel.cancel();
    }

    #[tokio::test]
    async fn the_seventeenth_connection_from_one_ip_is_refused() {
        use tokio::io::AsyncReadExt;
        let pki = Pki::new();
        let (addr, _hub, cancel, _t) = start(&pki, HashSet::new()).await;
        let mut held = Vec::new();
        for _ in 0..16 {
            held.push(TcpStream::connect(&addr).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut extra = TcpStream::connect(&addr).await.unwrap();
        let mut buf = [0u8; 1];
        let r = tokio::time::timeout(Duration::from_secs(3), extra.read(&mut buf))
            .await
            .expect("the refused connection must be closed promptly");
        assert!(matches!(r, Ok(0) | Err(_)));
        cancel.cancel();
    }

    #[tokio::test]
    async fn cancelling_closes_the_listener() {
        let pki = Pki::new();
        let host = Uuid::new_v4();
        pki.agent("a", host);
        let (addr, hub, cancel, task) = start(&pki, HashSet::new()).await;
        let (ccancel, _ct) = client(&pki, &addr, "a", Arc::new(Fake::default()));
        wait_connected(&hub, host).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("listener must stop")
            .unwrap();
        for _ in 0..40 {
            if !hub.connected(host) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!hub.connected(host));
        ccancel.cancel();
    }

    #[test]
    fn agent_version_is_bounded_and_sanitized() {
        assert_eq!(
            sanitize_agent_version(
                "1.2
[31m"
            ),
            "1.2??[31m"
        );
        assert_eq!(sanitize_agent_version(&"a".repeat(500)).chars().count(), 64);
    }

    #[tokio::test]
    async fn a_duplicate_pending_command_id_is_rejected() {
        let pki = Pki::new();
        let host = Uuid::new_v4();
        pki.agent("a", host);
        let (addr, hub, cancel, _t) = start(&pki, HashSet::new()).await;
        let (ccancel, _ct) = client(&pki, &addr, "a", Arc::new(Fake::default()));
        wait_connected(&hub, host).await;
        let first = cmd(host, 800);
        let h2 = hub.clone();
        let f2 = first.clone();
        let p = tokio::spawn(async move { h2.send(host, f2, Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        let dup = hub.send(host, first, Duration::from_secs(5)).await;
        assert_eq!(dup, Err(SendError::Duplicate));
        assert!(matches!(
            p.await.unwrap(),
            Ok(CommandResult::DryRunOk { .. })
        ));
        ccancel.cancel();
        cancel.cancel();
    }

    #[tokio::test]
    async fn no_command_reaches_a_replaced_connection() {
        use crate::frame::{read_frame, write_frame};
        // Fake old agent: a bare mTLS-less duplex is not possible with the
        // server, so use a real TLS client that records frames.
        let pki = Pki::new();
        let host = Uuid::new_v4();
        pki.agent("a", host);
        pki.agent("b", host);
        let (addr, hub, cancel, _t) = start(&pki, HashSet::new()).await;
        let tlsc = tls::client_config(&pki.p("ca.pem"), &pki.p("a.pem"), &pki.p("a.key")).unwrap();
        let tcp = TcpStream::connect(&addr).await.unwrap();
        let mut old = TlsConnector::from(tlsc)
            .connect(ServerName::try_from("localhost".to_string()).unwrap(), tcp)
            .await
            .unwrap();
        write_frame(
            &mut old,
            &ControlClientMsg::Hello {
                agent_version: "t".into(),
            },
        )
        .await
        .unwrap();
        wait_connected(&hub, host).await;
        let (bcancel, _bt) = client(&pki, &addr, "b", Arc::new(Fake::default()));
        // The server closes the old connection once b replaces it.
        let mut delivered = 0;
        loop {
            match tokio::time::timeout(
                Duration::from_secs(5),
                read_frame::<_, ControlServerMsg>(&mut old),
            )
            .await
            .expect("old connection must be closed on replacement")
            {
                Ok(ControlServerMsg::Command(_)) => delivered += 1,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        // Sends racing the close must be served by b only, never by old.
        let mut sends = Vec::new();
        for _ in 0..20 {
            let h = hub.clone();
            sends.push(tokio::spawn(async move {
                h.send(host, cmd(host, 0), Duration::from_secs(5)).await
            }));
        }
        for s in sends {
            assert!(s.await.unwrap().is_ok());
        }
        assert_eq!(delivered, 0, "old connection received commands");
        bcancel.cancel();
        cancel.cancel();
    }

    #[tokio::test]
    async fn backoff_resets_only_after_the_server_answers() {
        use crate::frame::write_frame;
        let handler: Arc<dyn CommandHandler> = Arc::new(Fake::default());
        let cancel = CancellationToken::new();

        // Rejected: peer closes without a frame.
        let (client_io, peer) = tokio::io::duplex(4096);
        drop(peer);
        let mut b = Backoff::default();
        b.next_delay();
        b.next_delay();
        assert!(control_session(client_io, &handler, &cancel, &mut b)
            .await
            .is_err());
        assert_eq!(b.next_delay(), Duration::from_secs(4));

        // Accepted: peer sends a Ping first.
        let (client_io, mut peer) = tokio::io::duplex(4096);
        write_frame(&mut peer, &ControlServerMsg::Ping)
            .await
            .unwrap();
        let mut b = Backoff::default();
        b.next_delay();
        b.next_delay();
        let c2 = cancel.clone();
        let h2 = handler.clone();
        let task = tokio::spawn(async move {
            let r = control_session(client_io, &h2, &c2, &mut b).await;
            (r, b)
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(peer);
        let (r, mut b) = task.await.unwrap();
        assert!(r.is_err());
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }
}
