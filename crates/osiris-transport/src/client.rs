//! The Agent side of the transport: the Forwarder tails the Agent's durable
//! spool file and ships batches to the Server, advancing a persisted offset only
//! after the Server acknowledges each batch (at-least-once delivery).

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use osiris_schema::CanonicalEvent;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::frame::{read_frame, write_frame};
use crate::tls::{client_config, TlsError};
use crate::wire::{ClientMsg, ServerMsg};

/// Most events sent in one batch.
const BATCH_MAX_EVENTS: usize = 500;
/// Most spool bytes read for one batch (also bounds one line's length).
const BATCH_MAX_BYTES: usize = 4 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct ForwarderConfig {
    pub server_addr: String,
    /// The name the Server's certificate must be valid for.
    pub server_name: String,
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub spool_path: PathBuf,
    pub ack_timeout: Duration,
}

impl ForwarderConfig {
    pub fn new(
        server_addr: impl Into<String>,
        server_name: impl Into<String>,
        ca: impl Into<PathBuf>,
        cert: impl Into<PathBuf>,
        key: impl Into<PathBuf>,
        spool_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            server_addr: server_addr.into(),
            server_name: server_name.into(),
            ca: ca.into(),
            cert: cert.into(),
            key: key.into(),
            spool_path: spool_path.into(),
            ack_timeout: Duration::from_secs(30),
        }
    }
}

/// Where the acknowledged offset lives: `<spool>.offset`.
pub fn offset_path(spool: &Path) -> PathBuf {
    let mut name = spool.as_os_str().to_owned();
    name.push(".offset");
    PathBuf::from(name)
}

fn load_offset(spool: &Path) -> u64 {
    std::fs::read_to_string(offset_path(spool))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn store_offset(spool: &Path, offset: u64) -> std::io::Result<()> {
    let path = offset_path(spool);
    let tmp = path.with_extension("offset.tmp");
    std::fs::write(&tmp, offset.to_string())?;
    std::fs::rename(&tmp, &path)
}

/// One batch read from the spool.
struct Batch {
    events: Vec<CanonicalEvent>,
    /// Spool bytes covered (including unparsable lines, which are skipped).
    consumed: u64,
}

enum ReadOutcome {
    Batch(Batch),
    Idle,
    /// The spool is shorter than the offset: it was truncated or rotated.
    Truncated,
}

fn read_batch(spool: &Path, offset: u64) -> std::io::Result<ReadOutcome> {
    let mut file = match std::fs::File::open(spool) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ReadOutcome::Idle),
        Err(e) => return Err(e),
    };
    let len = file.metadata()?.len();
    if len < offset {
        return Ok(ReadOutcome::Truncated);
    }
    if len == offset {
        return Ok(ReadOutcome::Idle);
    }
    file.seek(SeekFrom::Start(offset))?;
    let want = (len - offset).min(BATCH_MAX_BYTES as u64);
    let mut chunk = Vec::with_capacity(want as usize);
    (&mut file).take(want).read_to_end(&mut chunk)?;

    let mut events = Vec::new();
    let mut consumed = 0usize;
    let mut lines = 0usize;
    while lines < BATCH_MAX_EVENTS {
        let Some(nl) = chunk[consumed..].iter().position(|b| *b == b'\n') else {
            break;
        };
        let line = &chunk[consumed..consumed + nl];
        consumed += nl + 1;
        lines += 1;
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<CanonicalEvent>(line) {
            Ok(event) => events.push(event),
            Err(e) => tracing::warn!(error = %e, "skipping an unparsable spool line"),
        }
    }
    if consumed == 0 {
        if chunk.len() >= BATCH_MAX_BYTES {
            // One line longer than the whole read window: skip it rather than stall.
            tracing::error!("spool line exceeds {BATCH_MAX_BYTES} bytes; skipping the window");
            return Ok(ReadOutcome::Batch(Batch {
                events: vec![],
                consumed: chunk.len() as u64,
            }));
        }
        return Ok(ReadOutcome::Idle); // a partial last line: wait for the rest
    }
    Ok(ReadOutcome::Batch(Batch {
        events,
        consumed: consumed as u64,
    }))
}

/// Runs until `cancel` fires. Returns an error only if the TLS material is unusable.
pub async fn run_forwarder(
    config: ForwarderConfig,
    cancel: CancellationToken,
) -> Result<(), TlsError> {
    let tls = client_config(&config.ca, &config.cert, &config.key)?;
    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|e| TlsError::Rustls(format!("invalid server_name: {e}")))?;
    let connector = TlsConnector::from(Arc::clone(&tls));

    let mut offset = load_offset(&config.spool_path);
    let mut seq: u64 = 0;
    let mut backoff = BACKOFF_MIN;

    'connect: loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        let stream = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect(&config.server_addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            other => {
                let why = match other {
                    Ok(Err(e)) => e.to_string(),
                    _ => "connect timed out".to_string(),
                };
                tracing::warn!(addr = %config.server_addr, %why, "forwarder cannot reach the server");
                if sleep_or_cancel(backoff, &cancel).await {
                    return Ok(());
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue 'connect;
            }
        };
        let mut conn = match tokio::time::timeout(
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
                tracing::warn!(%why, "forwarder tls handshake failed");
                if sleep_or_cancel(backoff, &cancel).await {
                    return Ok(());
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue 'connect;
            }
        };
        backoff = BACKOFF_MIN;
        tracing::info!(addr = %config.server_addr, "forwarder connected");

        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let batch = match read_batch(&config.spool_path, offset) {
                Ok(ReadOutcome::Batch(b)) => b,
                Ok(ReadOutcome::Idle) => {
                    if sleep_or_cancel(POLL_INTERVAL, &cancel).await {
                        return Ok(());
                    }
                    continue;
                }
                Ok(ReadOutcome::Truncated) => {
                    tracing::warn!("spool shrank below the acknowledged offset; restarting from 0");
                    offset = 0;
                    let _ = store_offset(&config.spool_path, 0);
                    continue;
                }
                Err(e) => {
                    tracing::error!(error = %e, "forwarder cannot read the spool");
                    if sleep_or_cancel(backoff, &cancel).await {
                        return Ok(());
                    }
                    continue;
                }
            };

            if !batch.events.is_empty() {
                seq += 1;
                let sent = write_frame(
                    &mut conn,
                    &ClientMsg::Batch {
                        seq,
                        events: batch.events,
                    },
                )
                .await;
                let reply = match sent {
                    Ok(()) => {
                        tokio::time::timeout(
                            config.ack_timeout,
                            read_frame::<_, ServerMsg>(&mut conn),
                        )
                        .await
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "forwarder send failed; reconnecting");
                        if sleep_or_cancel(backoff, &cancel).await {
                            return Ok(());
                        }
                        continue 'connect;
                    }
                };
                match reply {
                    Ok(Ok(ServerMsg::Ack { seq: acked })) if acked == seq => {}
                    Ok(Ok(ServerMsg::Nack {
                        permanent: true,
                        reason,
                        ..
                    })) => {
                        tracing::error!(%reason, "server permanently rejected a batch; skipping it");
                    }
                    Ok(Ok(other)) => {
                        tracing::warn!(?other, "batch not acknowledged; retrying");
                        if sleep_or_cancel(backoff, &cancel).await {
                            return Ok(());
                        }
                        continue 'connect;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "connection lost awaiting an ack; reconnecting");
                        if sleep_or_cancel(backoff, &cancel).await {
                            return Ok(());
                        }
                        continue 'connect;
                    }
                    Err(_) => {
                        tracing::warn!("timed out awaiting an ack; reconnecting");
                        continue 'connect;
                    }
                }
            }
            offset += batch.consumed;
            if let Err(e) = store_offset(&config.spool_path, offset) {
                tracing::error!(error = %e, "cannot persist the forwarder offset (events may be resent after a restart)");
            }
        }
    }
}

/// Sleeps for `d`; returns `true` if cancelled first.
async fn sleep_or_cancel(d: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => false,
        _ = cancel.cancelled() => true,
    }
}
