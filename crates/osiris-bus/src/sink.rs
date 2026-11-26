use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use osiris_schema::CanonicalEvent;
use thiserror::Error;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Error)]
pub enum SinkError {
    #[error("failed to write to spool file at {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to serialize event: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Where the drain loop (bus.rs) forwards each dequeued event. The Phase 1
/// substitute for the real UDS Agent→Server transport (plan Global
/// Constraints #3) is `SpoolFileSink`; `InMemorySink` exists for tests.
#[async_trait]
pub trait Sink: Send + Sync {
    async fn send(&self, event: CanonicalEvent) -> Result<(), SinkError>;
}

/// Appends each event as one NDJSON line to a local file. The Server binary
/// (Task 8) tails this same path and ingests via `Storage::batch_write` —
/// this is the entire Agent→Server "transport" for Phase 1. A tokio Mutex
/// serializes concurrent `send` calls; each `send` returns only once its
/// complete line (event + `\n`) has been written.
///
/// Phase 13a (spec §5.2b): a spool file this sink creates starts with a
/// header line naming it (`osiris_fileutil::spool`), and with `max_bytes`
/// set the sink rotates `<spool>` to `<spool>.1` before a line that would
/// take it past the cap. Readers follow the rotation by the header id.
pub struct SpoolFileSink {
    path: PathBuf,
    max_bytes: Option<u64>,
    /// Held across each whole send, rotation included, so no append can
    /// land between the rename and the new file's header.
    state: tokio::sync::Mutex<SpoolState>,
}

/// What the sink knows about the current spool file without a stat per
/// send. Only this sink writes the file, so it stays accurate.
struct SpoolState {
    /// Bytes in the file.
    len: u64,
    /// Bytes of the header line at its start (0 for a legacy file). The
    /// file holds at least one event iff `len > header_len`.
    header_len: u64,
}

impl SpoolFileSink {
    /// `open_with(path, None)`: a spool that never rotates.
    pub async fn open(path: impl Into<PathBuf>) -> Result<Self, SinkError> {
        Self::open_with(path, None).await
    }

    /// Creates the spool file if it does not already exist, with a header
    /// line if it is new or empty. Never truncates or rewrites an existing
    /// file — the Server may already be tailing it — so a legacy spool
    /// stays header-less until its first rotation. `max_bytes` caps each
    /// spool file (`None` = never rotate).
    pub async fn open_with(
        path: impl Into<PathBuf>,
        max_bytes: Option<u64>,
    ) -> Result<Self, SinkError> {
        let path = path.into();
        let state = ensure_header(&path)
            .await
            .map_err(|source| SinkError::Write {
                path: path.clone(),
                source,
            })?;
        Ok(Self {
            path,
            max_bytes,
            state: tokio::sync::Mutex::new(state),
        })
    }

    /// Renames the spool to `<spool>.1`, replacing an older `.1`, and puts a
    /// new, already-headered spool in its place. Called with the state lock
    /// held. The new file is prepared first, so a failure there leaves the
    /// spool untouched; between the two renames `<spool>` is briefly
    /// missing, which readers handle (`osiris_fileutil::spool::locate`).
    async fn rotate(&self, state: &mut SpoolState) -> std::io::Result<()> {
        let (tmp, header_len) = write_headered_tmp(&self.path).await?;
        let rotated = osiris_fileutil::spool::rotated_path(&self.path);
        tokio::fs::rename(&self.path, &rotated).await?;
        tokio::fs::rename(&tmp, &self.path).await?;
        *state = SpoolState {
            len: header_len,
            header_len,
        };
        Ok(())
    }
}

fn spool_open_options() -> tokio::fs::OpenOptions {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut options = tokio::fs::OpenOptions::new();
    #[cfg(unix)]
    options.mode(0o640);
    options
}

/// Writes a fresh header (new uuid v7) to `<spool>.tmp`, truncating any
/// leftover from a crash, and syncs it. Returns the tmp path and the
/// header's length.
async fn write_headered_tmp(spool: &std::path::Path) -> std::io::Result<(PathBuf, u64)> {
    let mut tmp = spool.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let header = osiris_fileutil::spool::header_line(&uuid::Uuid::now_v7().to_string());
    let mut file = spool_open_options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)
        .await?;
    file.write_all(header.as_bytes()).await?;
    file.flush().await?;
    file.sync_all().await?;
    Ok((tmp, header.len() as u64))
}

/// Makes sure a spool exists at `path` and returns its state. A missing or
/// empty spool is replaced by a headered one via `<spool>.tmp` + rename, so
/// no reader ever sees a new spool without its header. An existing
/// non-empty spool is left exactly as it is (a legacy one keeps no header).
async fn ensure_header(path: &std::path::Path) -> std::io::Result<SpoolState> {
    let len = match tokio::fs::metadata(path).await {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e),
    };
    if len == 0 {
        let (tmp, header_len) = write_headered_tmp(path).await?;
        tokio::fs::rename(&tmp, path).await?;
        return Ok(SpoolState {
            len: header_len,
            header_len,
        });
    }
    let header_len = match osiris_fileutil::spool::read_spool_id(path)? {
        Some(id) => osiris_fileutil::spool::header_line(&id).len() as u64,
        None => 0,
    };
    Ok(SpoolState { len, header_len })
}

#[async_trait]
impl Sink for SpoolFileSink {
    async fn send(&self, event: CanonicalEvent) -> Result<(), SinkError> {
        // One buffer, one append: the line and its terminator reach the
        // kernel in a single O_APPEND write, so no other append can land
        // between an event and its newline.
        let mut line = serde_json::to_string(&event)?;
        line.push('\n');
        let line_len = line.len() as u64;
        let write_err = |source| SinkError::Write {
            path: self.path.clone(),
            source,
        };
        let mut state = self.state.lock().await;
        if let Some(max) = self.max_bytes {
            // A file holding no event yet is never rotated: a line larger
            // than the cap still gets written, alone in its own file.
            if state.len > state.header_len && state.len + line_len > max {
                if let Err(e) = self.rotate(&mut state).await {
                    // Keep the event: append it to whatever file is at the
                    // path now (past the cap) rather than dropping it.
                    tracing::warn!(
                        path = %self.path.display(),
                        error = %e,
                        "spool rotation failed; appending past the size cap"
                    );
                    *state = ensure_header(&self.path).await.map_err(write_err)?;
                }
            }
        }
        let mut file = spool_open_options()
            .append(true)
            .open(&self.path)
            .await
            .map_err(write_err)?;
        file.write_all(line.as_bytes()).await.map_err(write_err)?;
        // tokio's File finishes a write on a blocking-pool task after
        // `write_all` returns, and dropping the handle does not wait for it.
        // Without this flush the previous send's bytes could land after the
        // next send's (Phase 10 real-Linux finding: two events on one line).
        file.flush().await.map_err(write_err)?;
        state.len += line_len;
        Ok(())
    }
}

/// Collects sent events in memory — used by bus.rs's own tests and by any
/// later crate's tests that need to observe what the bus forwarded without
/// touching the filesystem.
#[derive(Clone, Default)]
pub struct InMemorySink {
    events: Arc<Mutex<Vec<CanonicalEvent>>>,
}

impl InMemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<CanonicalEvent> {
        // A poisoned lock still holds a fully-formed Vec of whatever was
        // pushed before the panic — for this test-support struct, reading
        // that is more useful than propagating the poison, so recover
        // rather than unwrap.
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[async_trait]
impl Sink for InMemorySink {
    async fn send(&self, event: CanonicalEvent) -> Result<(), SinkError> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(event);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_fileutil::spool;
    use osiris_schema::{Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION};
    use uuid::Uuid;

    fn sample_event() -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1,
            monotonic_timestamp: 1,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef {
                host_id,
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

    #[tokio::test]
    async fn spool_file_sink_appends_one_ndjson_line_per_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        let sink = SpoolFileSink::open(&path).await.unwrap();
        sink.send(sample_event()).await.unwrap();
        sink.send(sample_event()).await.unwrap();

        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3, "header + two events");
        assert!(spool::is_header_line(lines[0].as_bytes()));
        let parsed: CanonicalEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed.event_type, EventType::ProcessExec);
    }

    #[tokio::test]
    async fn spool_file_sink_does_not_truncate_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        {
            let sink = SpoolFileSink::open(&path).await.unwrap();
            sink.send(sample_event()).await.unwrap();
        }
        {
            let sink = SpoolFileSink::open(&path).await.unwrap();
            sink.send(sample_event()).await.unwrap();
        }
        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(contents.lines().count(), 3, "one header + two events");
    }

    /// Real-Linux finding (Phase 10, Ubuntu 24.04 agent spool): two events
    /// landed on one line followed by an empty line, and the forwarder
    /// skipped the merged line as unparsable. Every line written by
    /// concurrent senders must be exactly one complete event, and every
    /// write must be on disk by the time `send` returns.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_senders_never_interleave_ndjson_lines() {
        const TASKS: usize = 16;
        const PER_TASK: usize = 50;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        let sink = Arc::new(SpoolFileSink::open(&path).await.unwrap());
        let handles: Vec<_> = (0..TASKS)
            .map(|_| {
                let sink = sink.clone();
                tokio::spawn(async move {
                    for _ in 0..PER_TASK {
                        sink.send(sample_event()).await.unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.await.unwrap();
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.ends_with('\n'), "the last line must be complete");
        let lines: Vec<&str> = contents.split_terminator('\n').collect();
        assert!(spool::is_header_line(lines[0].as_bytes()));
        let lines = &lines[1..];
        for (i, line) in lines.iter().enumerate() {
            serde_json::from_str::<CanonicalEvent>(line).unwrap_or_else(|e| {
                panic!("spool line {} is not one event ({e}): {line:.200}", i + 1)
            });
        }
        assert_eq!(lines.len(), TASKS * PER_TASK);
    }

    /// The root cause of the interleaving: tokio's `File::poll_write` hands
    /// the bytes to a blocking-pool task and returns before they are
    /// written; dropping the handle does not wait. So `send` N's trailing
    /// "\n" could still be pending when `send` N+1 wrote its line from a
    /// fresh handle. `send` must not return before its line is on disk.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_returns_only_after_the_whole_line_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        let sink = SpoolFileSink::open(&path).await.unwrap();
        let mut expected_len = std::fs::metadata(&path).unwrap().len();
        assert!(expected_len > 0, "the header is on disk once open returns");
        for i in 0..200 {
            let event = sample_event();
            expected_len += serde_json::to_string(&event).unwrap().len() as u64 + 1;
            sink.send(event).await.unwrap();
            let on_disk = std::fs::metadata(&path).unwrap().len();
            assert_eq!(
                on_disk, expected_len,
                "after send #{i} returned, the spool holds {on_disk} bytes, expected {expected_len}"
            );
        }
    }

    fn read_lines(path: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn event_line(event: &CanonicalEvent) -> String {
        let mut line = serde_json::to_string(event).unwrap();
        line.push('\n');
        line
    }

    fn header_id(line: &str) -> String {
        assert!(
            spool::is_header_line(line.as_bytes()),
            "not a spool header: {line}"
        );
        line.trim_start_matches("{\"osiris_spool\":\"")
            .trim_end_matches("\"}")
            .to_owned()
    }

    fn header_len() -> u64 {
        spool::header_line(&Uuid::now_v7().to_string()).len() as u64
    }

    #[tokio::test]
    async fn new_spool_starts_with_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        let sink = SpoolFileSink::open(&path).await.unwrap();
        let id = spool::read_spool_id(&path)
            .unwrap()
            .expect("a new spool carries a header");
        assert!(Uuid::parse_str(&id).is_ok(), "header id is a uuid: {id}");
        sink.send(sample_event()).await.unwrap();
        let lines = read_lines(&path);
        assert_eq!(lines.len(), 2);
        assert_eq!(header_id(&lines[0]), id);
        serde_json::from_str::<CanonicalEvent>(&lines[1]).unwrap();

        // An existing but empty spool gets one too.
        let empty = dir.path().join("empty.ndjson");
        std::fs::write(&empty, "").unwrap();
        SpoolFileSink::open(&empty).await.unwrap();
        assert!(spool::read_spool_id(&empty).unwrap().is_some());

        // Reopening keeps the header, and its id, as they are.
        drop(sink);
        SpoolFileSink::open(&path).await.unwrap();
        let reopened = read_lines(&path);
        assert_eq!(reopened.len(), 2);
        assert_eq!(header_id(&reopened[0]), id);
    }

    #[tokio::test]
    async fn existing_legacy_spool_gets_no_header_prepended() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        let legacy = event_line(&sample_event());
        std::fs::write(&path, &legacy).unwrap();
        let sink = SpoolFileSink::open_with(&path, Some(1 << 20))
            .await
            .unwrap();
        let second = sample_event();
        sink.send(second.clone()).await.unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, format!("{legacy}{}", event_line(&second)));
        assert_eq!(spool::read_spool_id(&path).unwrap(), None);
    }

    #[tokio::test]
    async fn rotates_when_next_line_would_exceed_max() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        let rotated = spool::rotated_path(&path);
        let events: Vec<CanonicalEvent> = (0..3).map(|_| sample_event()).collect();
        let line_len = event_line(&events[0]).len() as u64;
        let sink = SpoolFileSink::open_with(&path, Some(header_len() + 2 * line_len))
            .await
            .unwrap();
        let first_id = spool::read_spool_id(&path).unwrap().unwrap();
        sink.send(events[0].clone()).await.unwrap();
        sink.send(events[1].clone()).await.unwrap();
        assert!(!rotated.exists(), "exactly at the cap must not rotate");
        sink.send(events[2].clone()).await.unwrap();

        let old = read_lines(&rotated);
        assert_eq!(old.len(), 3);
        assert_eq!(header_id(&old[0]), first_id);
        assert_eq!(format!("{}\n", old[1]), event_line(&events[0]));
        assert_eq!(format!("{}\n", old[2]), event_line(&events[1]));

        let new = read_lines(&path);
        assert_eq!(new.len(), 2);
        assert_ne!(header_id(&new[0]), first_id, "rotation starts a new id");
        assert_eq!(format!("{}\n", new[1]), event_line(&events[2]));
    }

    #[tokio::test]
    async fn rotation_replaces_previous_dot1() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        let rotated = spool::rotated_path(&path);
        let events: Vec<CanonicalEvent> = (0..3).map(|_| sample_event()).collect();
        let line_len = event_line(&events[0]).len() as u64;
        let sink = SpoolFileSink::open_with(&path, Some(header_len() + line_len))
            .await
            .unwrap();
        sink.send(events[0].clone()).await.unwrap();
        sink.send(events[1].clone()).await.unwrap();
        let second_id = spool::read_spool_id(&path).unwrap().unwrap();
        sink.send(events[2].clone()).await.unwrap();

        let old = read_lines(&rotated);
        assert_eq!(old.len(), 2, "the older .1 was replaced, not appended to");
        assert_eq!(header_id(&old[0]), second_id);
        assert_eq!(format!("{}\n", old[1]), event_line(&events[1]));
        let new = read_lines(&path);
        assert_eq!(new.len(), 2);
        assert_eq!(format!("{}\n", new[1]), event_line(&events[2]));
    }

    /// Concurrent senders across one rotation: every event lands exactly
    /// once, whole, in `.1` or the new spool, and each file has one header.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_senders_across_a_rotation_lose_and_split_nothing() {
        const TASKS: usize = 16;
        const PER_TASK: usize = 10;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        let line_len = event_line(&sample_event()).len() as u64;
        let cap = header_len() + 100 * line_len;
        let sink = Arc::new(SpoolFileSink::open_with(&path, Some(cap)).await.unwrap());
        let handles: Vec<_> = (0..TASKS)
            .map(|_| {
                let sink = sink.clone();
                tokio::spawn(async move {
                    let mut ids = Vec::new();
                    for _ in 0..PER_TASK {
                        let event = sample_event();
                        ids.push(event.event_id);
                        sink.send(event).await.unwrap();
                    }
                    ids
                })
            })
            .collect();
        let mut sent = std::collections::HashSet::new();
        for handle in handles {
            sent.extend(handle.await.unwrap());
        }

        let mut seen = std::collections::HashSet::new();
        let mut per_file = Vec::new();
        for p in [spool::rotated_path(&path), path.clone()] {
            let lines = read_lines(&p);
            header_id(&lines[0]);
            for line in &lines[1..] {
                let event: CanonicalEvent = serde_json::from_str(line).unwrap();
                assert!(seen.insert(event.event_id), "duplicate event");
            }
            assert!(std::fs::metadata(&p).unwrap().len() <= cap);
            per_file.push(lines.len() - 1);
        }
        assert_eq!(per_file, vec![100, TASKS * PER_TASK - 100]);
        assert_eq!(seen, sent);
    }

    /// A headered spool must never be observable without its header: a
    /// reader that saw it empty or header-less would adopt `id: None` for
    /// it. An observer polls the spool path through many rotations; every
    /// time the path exists it must already start with a header.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_new_spool_is_never_observed_without_its_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observer = {
            let (path, stop) = (path.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut bad = Vec::new();
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    // Missing is fine (between the Agent's two renames).
                    if let Ok(bytes) = std::fs::read(&path) {
                        let first = bytes.split(|b| *b == b'\n').next().unwrap_or(&[]);
                        if !spool::is_header_line(first) {
                            bad.push(String::from_utf8_lossy(&bytes).into_owned());
                        }
                    }
                }
                bad
            })
        };
        // Cap 1: every send after the first rotates.
        let sink = SpoolFileSink::open_with(&path, Some(1)).await.unwrap();
        for _ in 0..300 {
            sink.send(sample_event()).await.unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let bad = observer.join().unwrap();
        assert!(
            bad.is_empty(),
            "observed {} header-less spool states, first: {:?}",
            bad.len(),
            bad.first()
        );
    }

    #[tokio::test]
    async fn a_stale_tmp_file_from_a_crash_does_not_leak_into_the_spool() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        let tmp = dir.path().join("spool.ndjson.tmp");
        std::fs::write(&tmp, "garbage from a crashed run\n").unwrap();
        let sink = SpoolFileSink::open_with(&path, Some(1)).await.unwrap();
        sink.send(sample_event()).await.unwrap();
        let lines = read_lines(&path);
        assert_eq!(lines.len(), 2, "{lines:?}");
        header_id(&lines[0]);
        assert!(!tmp.exists());
        std::fs::write(&tmp, "garbage again\n").unwrap();
        sink.send(sample_event()).await.unwrap();
        let lines = read_lines(&path);
        assert_eq!(lines.len(), 2, "after rotation: {lines:?}");
        header_id(&lines[0]);
        assert!(!tmp.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn spool_files_are_0640() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        let sink = SpoolFileSink::open_with(&path, Some(1)).await.unwrap();
        sink.send(sample_event()).await.unwrap();
        sink.send(sample_event()).await.unwrap();
        for p in [path.clone(), spool::rotated_path(&path)] {
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o640, "{}", p.display());
        }
    }

    #[tokio::test]
    async fn in_memory_sink_collects_events_in_order() {
        let sink = InMemorySink::new();
        sink.send(sample_event()).await.unwrap();
        sink.send(sample_event()).await.unwrap();
        assert_eq!(sink.events().len(), 2);
    }
}
