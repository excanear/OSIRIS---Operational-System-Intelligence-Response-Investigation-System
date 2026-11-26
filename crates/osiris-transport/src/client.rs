//! The Agent side of the transport: the Forwarder tails the Agent's durable
//! spool file and ships batches to the Server, advancing a persisted offset only
//! after the Server acknowledges each batch (at-least-once delivery).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use osiris_fileutil::spool::{is_header_line, CursorLoad, SpoolCursor};
use osiris_fileutil::SpoolReader;
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
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
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

/// Exponential reconnect delay, 1s doubling to 30s; reset only once a batch is acked.
pub(crate) struct Backoff(Duration);

impl Default for Backoff {
    fn default() -> Self {
        Self(BACKOFF_MIN)
    }
}

impl Backoff {
    /// The delay to wait now; the next call returns double (capped).
    pub(crate) fn next_delay(&mut self) -> Duration {
        let d = self.0;
        self.0 = (self.0 * 2).min(BACKOFF_MAX);
        d
    }

    pub(crate) fn reset(&mut self) {
        self.0 = BACKOFF_MIN;
    }
}

/// Where the acknowledged cursor lives: `<spool>.offset`. It holds a
/// [`SpoolCursor`] (`"<spool id> <offset>"`); a pre-13a bare offset still
/// loads, as a position in a legacy (header-less) spool.
pub fn offset_path(spool: &Path) -> PathBuf {
    let mut name = spool.as_os_str().to_owned();
    name.push(".offset");
    PathBuf::from(name)
}

fn load_cursor(spool: &Path) -> CursorLoad {
    SpoolCursor::load(&offset_path(spool))
}

fn store_cursor(spool: &Path, cursor: &SpoolCursor) -> std::io::Result<()> {
    cursor.store(&offset_path(spool))
}

/// One batch read from one spool file.
struct Batch {
    events: Vec<CanonicalEvent>,
    /// Bytes of that file covered (including header, blank and unparsable
    /// lines, which are skipped).
    consumed: u64,
    /// Lines that were neither events nor spool headers (each one logged).
    #[cfg_attr(not(test), allow(dead_code))]
    unparsable: usize,
}

enum ReadOutcome {
    Batch(Batch),
    Idle,
}

/// Reads the next batch from the file `reader` points into (never from two
/// files: `consumed` is always relative to that one file). The caller
/// advances `reader` by `consumed` only once the batch is acknowledged.
fn read_batch(reader: &mut SpoolReader) -> std::io::Result<ReadOutcome> {
    let Some(mut open) = reader.open()? else {
        return Ok(ReadOutcome::Idle);
    };
    if open.len <= open.offset {
        return Ok(ReadOutcome::Idle);
    }
    let want = (open.len - open.offset).min(BATCH_MAX_BYTES as u64);
    let mut chunk = Vec::with_capacity(want as usize);
    (&mut open.file).take(want).read_to_end(&mut chunk)?;

    let mut events = Vec::new();
    let mut unparsable = 0usize;
    let mut consumed = 0usize;
    let mut lines = 0usize;
    while lines < BATCH_MAX_EVENTS {
        let Some(nl) = chunk[consumed..].iter().position(|b| *b == b'\n') else {
            break;
        };
        let line = &chunk[consumed..consumed + nl];
        consumed += nl + 1;
        if line.is_empty() || is_header_line(line) {
            continue;
        }
        lines += 1;
        match serde_json::from_slice::<CanonicalEvent>(line) {
            Ok(event) => events.push(event),
            Err(e) => {
                unparsable += 1;
                tracing::warn!(error = %e, "skipping an unparsable spool line");
            }
        }
    }
    if consumed == 0 {
        if chunk.len() >= BATCH_MAX_BYTES {
            // One line longer than the whole read window: skip it rather than stall.
            tracing::error!("spool line exceeds {BATCH_MAX_BYTES} bytes; skipping the window");
        } else if open.rotated {
            // The rotated file ends in a torn line that will never complete.
            tracing::warn!("skipping a partial last line of the rotated spool");
        } else {
            return Ok(ReadOutcome::Idle); // a partial last line: wait for the rest
        }
        return Ok(ReadOutcome::Batch(Batch {
            events: vec![],
            consumed: chunk.len() as u64,
            unparsable: 1,
        }));
    }
    Ok(ReadOutcome::Batch(Batch {
        events,
        consumed: consumed as u64,
        unparsable,
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

    let mut reader = SpoolReader::new(&config.spool_path, load_cursor(&config.spool_path));
    let mut losses = LossReport::default();
    losses.check(&reader);
    let mut seq: u64 = 0;
    let mut backoff = Backoff::default();
    let mut permanently_rejected: u64 = 0;

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
                if sleep_or_cancel(backoff.next_delay(), &cancel).await {
                    return Ok(());
                }
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
                if sleep_or_cancel(backoff.next_delay(), &cancel).await {
                    return Ok(());
                }
                continue 'connect;
            }
        };
        tracing::info!(addr = %config.server_addr, "forwarder connected");

        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let read = read_batch(&mut reader);
            losses.check(&reader);
            let batch = match read {
                Ok(ReadOutcome::Batch(b)) => b,
                Ok(ReadOutcome::Idle) => {
                    if sleep_or_cancel(POLL_INTERVAL, &cancel).await {
                        return Ok(());
                    }
                    continue;
                }
                Err(e) => {
                    tracing::error!(error = %e, "forwarder cannot read the spool");
                    if sleep_or_cancel(backoff.next_delay(), &cancel).await {
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
                        if sleep_or_cancel(backoff.next_delay(), &cancel).await {
                            return Ok(());
                        }
                        continue 'connect;
                    }
                };
                match reply {
                    Ok(Ok(ServerMsg::Ack { seq: acked })) if acked == seq => {
                        backoff.reset();
                    }
                    Ok(Ok(ServerMsg::Nack {
                        permanent: true,
                        reason,
                        ..
                    })) => {
                        permanently_rejected += 1;
                        tracing::error!(%reason, permanently_rejected, "server permanently rejected a batch; skipping it");
                    }
                    Ok(Ok(other)) => {
                        tracing::warn!(?other, "batch not acknowledged; retrying");
                        if sleep_or_cancel(backoff.next_delay(), &cancel).await {
                            return Ok(());
                        }
                        continue 'connect;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "connection lost awaiting an ack; reconnecting");
                        if sleep_or_cancel(backoff.next_delay(), &cancel).await {
                            return Ok(());
                        }
                        continue 'connect;
                    }
                    Err(_) => {
                        tracing::warn!("timed out awaiting an ack; reconnecting");
                        if sleep_or_cancel(backoff.next_delay(), &cancel).await {
                            return Ok(());
                        }
                        continue 'connect;
                    }
                }
            }
            reader.advance(batch.consumed);
            if let Some(cursor) = reader.cursor() {
                if let Err(e) = store_cursor(&config.spool_path, cursor) {
                    tracing::error!(error = %e, "cannot persist the forwarder offset (events may be resent after a restart)");
                }
            }
        }
    }
}

/// Logs each newly counted loss or truncation of a [`SpoolReader`] once.
#[derive(Default)]
struct LossReport {
    lost_rotations: u64,
    truncations: u64,
}

impl LossReport {
    fn check(&mut self, reader: &SpoolReader) {
        if reader.lost_rotations() > self.lost_rotations {
            self.lost_rotations = reader.lost_rotations();
            tracing::warn!(
                lost_rotations = self.lost_rotations,
                "the forwarder's spool position is gone (more than one rotation behind, or an \
                 unreadable offset file); unsent events were lost, restarting at the current spool"
            );
        }
        if reader.truncations() > self.truncations {
            self.truncations = reader.truncations();
            tracing::warn!("spool shrank below the acknowledged offset; restarting from 0");
        }
    }
}

/// Sleeps for `d`; returns `true` if cancelled first.
pub(crate) async fn sleep_or_cancel(d: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => false,
        _ = cancel.cancelled() => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use osiris_fileutil::spool::{header_line, rotated_path, CursorLoad, SpoolCursor};
    use osiris_fileutil::SpoolReader;
    use osiris_schema::{Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION};

    const ID_A: &str = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const ID_B: &str = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";

    fn event(n: u64) -> CanonicalEvent {
        let host = uuid::Uuid::nil();
        CanonicalEvent {
            event_id: uuid::Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id: host,
            boot_id: "b".to_string(),
            timestamp: n,
            monotonic_timestamp: n,
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

    fn event_lines(ns: &[u64]) -> String {
        ns.iter()
            .map(|n| serde_json::to_string(&event(*n)).unwrap() + "\n")
            .collect()
    }

    fn append(path: &Path, text: &str) {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }

    /// The `SpoolFileSink` rotation: headered `.tmp`, spool → `.1`, `.tmp` → spool.
    fn rotate(spool: &Path, new_id: &str, text: &str) {
        let mut tmp = spool.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, header_line(new_id) + text).unwrap();
        std::fs::rename(spool, rotated_path(spool)).unwrap();
        std::fs::rename(&tmp, spool).unwrap();
    }

    /// One forwarder step as `run_forwarder` does it after an ack.
    fn next(reader: &mut SpoolReader) -> Option<Batch> {
        match read_batch(reader).unwrap() {
            ReadOutcome::Batch(batch) => {
                reader.advance(batch.consumed);
                Some(batch)
            }
            ReadOutcome::Idle => None,
        }
    }

    fn stamps(batch: &Batch) -> Vec<u64> {
        batch.events.iter().map(|e| e.timestamp).collect()
    }

    #[test]
    fn forwarder_cursor_loads_legacy_offset_file() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        std::fs::write(offset_path(&spool), "4096\n").unwrap();
        assert_eq!(
            load_cursor(&spool),
            CursorLoad::Loaded(SpoolCursor {
                id: None,
                offset: 4096
            })
        );

        // A legacy cursor resumes a legacy spool where it left off.
        let first = event_lines(&[1]);
        std::fs::write(&spool, first.clone() + &event_lines(&[2])).unwrap();
        std::fs::write(offset_path(&spool), first.len().to_string()).unwrap();
        let mut reader = SpoolReader::new(&spool, load_cursor(&spool));
        assert_eq!(stamps(&next(&mut reader).unwrap()), [2]);
    }

    #[test]
    fn forwarder_finishes_rotated_file_before_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        std::fs::write(&spool, header_line(ID_A) + &event_lines(&[1])).unwrap();
        let mut reader = SpoolReader::new(&spool, load_cursor(&spool));
        assert_eq!(stamps(&next(&mut reader).unwrap()), [1]);

        append(&spool, &event_lines(&[2, 3]));
        rotate(&spool, ID_B, &event_lines(&[4, 5, 6, 7, 8]));

        let old = next(&mut reader).unwrap();
        assert_eq!(stamps(&old), [2, 3], "the rest of .1, and nothing else");
        let new = next(&mut reader).unwrap();
        assert_eq!(stamps(&new), [4, 5, 6, 7, 8]);
        assert!(next(&mut reader).is_none());

        let cursor = reader.cursor().unwrap().clone();
        assert_eq!(cursor.id.as_deref(), Some(ID_B));
        assert_eq!(cursor.offset, std::fs::metadata(&spool).unwrap().len());
        store_cursor(&spool, &cursor).unwrap();
        assert_eq!(load_cursor(&spool), CursorLoad::Loaded(cursor));
    }

    #[test]
    fn forwarder_skips_header_without_warning() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        std::fs::write(&spool, header_line(ID_A) + &event_lines(&[1])).unwrap();
        let mut reader = SpoolReader::new(&spool, load_cursor(&spool));
        let batch = next(&mut reader).unwrap();
        assert_eq!(stamps(&batch), [1]);
        assert_eq!(batch.unparsable, 0, "the header is not an unparsable event");
        assert_eq!(batch.consumed, std::fs::metadata(&spool).unwrap().len());
    }

    #[test]
    fn forwarder_never_reads_across_the_switch() {
        // A rotation while the forwarder still has unacked bytes of the old
        // file: the retried read must come from `.1` at the same offset.
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        std::fs::write(&spool, header_line(ID_A) + &event_lines(&[1, 2])).unwrap();
        let mut reader = SpoolReader::new(&spool, load_cursor(&spool));
        let ReadOutcome::Batch(unacked) = read_batch(&mut reader).unwrap() else {
            panic!("expected a batch");
        };
        assert_eq!(stamps(&unacked), [1, 2]);

        rotate(&spool, ID_B, &event_lines(&[3]));
        assert_eq!(
            stamps(&next(&mut reader).unwrap()),
            [1, 2],
            "resent from .1"
        );
        assert_eq!(stamps(&next(&mut reader).unwrap()), [3]);
    }

    #[test]
    fn backoff_grows_to_the_cap_and_resets_only_on_reset() {
        let mut b = Backoff::default();
        let got: Vec<u64> = (0..7).map(|_| b.next_delay().as_secs()).collect();
        assert_eq!(got, [1, 2, 4, 8, 16, 30, 30]);
        b.reset();
        assert_eq!(b.next_delay(), BACKOFF_MIN);
    }
}
