//! Rotation-aware spool readers (Phase 13a, spec §5.2b).
//!
//! [`SpoolReader`] keeps a reader's [`SpoolCursor`] and, each time it is
//! asked, opens the file that cursor now points into, following the Agent's
//! `<spool>` → `<spool>.1` rotation. [`SpoolTailer`] is the line tailer the
//! Server's same-host ingestion uses on top of it, with an optional durable
//! cursor file. The forwarder (osiris-transport) drives a `SpoolReader`
//! directly, because it advances only after the Server acknowledges a batch.
//!
//! Std-only and without logging, like the rest of this crate: losses and
//! truncations are exposed as counters for the caller to log.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Mutex;

use crate::spool::{
    is_header_line, locate, read_spool_id_from, rotated_path, CursorLoad, SpoolCursor,
    SpoolPosition,
};

/// How many times [`SpoolReader::open`] re-decides when the file it opened
/// turned out not to be the one [`locate`] named (a rotation in between).
const MAX_RELOCATES: usize = 4;

/// A spool file opened at the reader's position: `file` is positioned at
/// `offset`, and `len` is its length measured on this handle. Read at most
/// `len - offset` bytes from it.
pub struct OpenSpool {
    pub file: File,
    pub offset: u64,
    pub len: u64,
    /// The file is `<spool>.1`: the Agent no longer writes it, so whatever
    /// remains after its last `\n` will never be completed.
    pub rotated: bool,
}

/// A reader's position in a rotating spool.
///
/// The cursor is `None` while the reader is waiting to begin the current
/// file at 0 (no cursor yet, or after a loss) and the current file does
/// not exist (between the Agent's two renames).
pub struct SpoolReader {
    spool: PathBuf,
    cursor: Option<SpoolCursor>,
    lost_rotations: u64,
    truncations: u64,
}

impl SpoolReader {
    /// Starts from what [`SpoolCursor::load`] found. `Missing` begins the
    /// current file at 0; `Garbled` is counted as one lost rotation, then
    /// does the same.
    pub fn new(spool: impl Into<PathBuf>, load: CursorLoad) -> Self {
        let (cursor, lost_rotations) = match load {
            CursorLoad::Missing => (None, 0),
            CursorLoad::Garbled => (None, 1),
            CursorLoad::Loaded(cursor) => (Some(cursor), 0),
        };
        Self {
            spool: spool.into(),
            cursor,
            lost_rotations,
            truncations: 0,
        }
    }

    /// Opens the file the cursor points into, positioned at the cursor's
    /// offset. A drained `<spool>.1` is left for the current file at 0, and
    /// a lost position is counted and replaced the same way; both update
    /// the cursor. `None` = nothing to read now (the file is missing).
    ///
    /// The id is checked on the opened handle itself, so a rotation
    /// between deciding and opening never pairs a new file with an offset
    /// meant for the old one.
    pub fn open(&mut self) -> std::io::Result<Option<OpenSpool>> {
        for _ in 0..MAX_RELOCATES {
            let Some(cursor) = self.cursor.clone() else {
                return self.begin_current();
            };
            match locate(&self.spool, Some(&cursor))? {
                SpoolPosition::Current { offset } => {
                    let Some((file, id)) = open_with_id(&self.spool)? else {
                        continue;
                    };
                    if id != cursor.id {
                        continue;
                    }
                    let len = file.metadata()?.len();
                    let offset = if len < offset {
                        // Truncated in place: restart it (the existing rule).
                        self.truncations += 1;
                        self.cursor = Some(SpoolCursor { id, offset: 0 });
                        0
                    } else {
                        offset
                    };
                    return positioned(file, offset, len, false).map(Some);
                }
                SpoolPosition::Rotated { offset } => {
                    let Some((file, id)) = open_with_id(&rotated_path(&self.spool))? else {
                        continue;
                    };
                    if id != cursor.id {
                        continue;
                    }
                    let len = file.metadata()?.len();
                    if offset >= len {
                        // `.1` is finished. The cursor keeps pointing at its
                        // end until the current file exists, so a restart in
                        // between resumes here rather than losing anything.
                        return self.begin_current();
                    }
                    return positioned(file, offset, len, true).map(Some);
                }
                SpoolPosition::Lost => {
                    // A legacy cursor that had read nothing cannot have
                    // lost anything (Agent upgraded under an idle reader).
                    if cursor.id.is_some() || cursor.offset > 0 {
                        self.lost_rotations += 1;
                    }
                    self.cursor = None;
                }
                SpoolPosition::Start => self.cursor = None,
            }
        }
        Ok(None)
    }

    /// Begins the current file at 0, storing the id of the handle opened.
    /// If it does not exist yet the cursor is left as it is.
    fn begin_current(&mut self) -> std::io::Result<Option<OpenSpool>> {
        let Some((file, id)) = open_with_id(&self.spool)? else {
            return Ok(None);
        };
        let len = file.metadata()?.len();
        self.cursor = Some(SpoolCursor { id, offset: 0 });
        positioned(file, 0, len, false).map(Some)
    }

    /// Moves the cursor `bytes` further into the file the last
    /// [`SpoolReader::open`] returned.
    pub fn advance(&mut self, bytes: u64) {
        if let Some(cursor) = &mut self.cursor {
            cursor.offset += bytes;
        } else {
            debug_assert_eq!(bytes, 0, "advance without an open spool file");
        }
    }

    /// The position to persist. `None` = nothing new to store.
    pub fn cursor(&self) -> Option<&SpoolCursor> {
        self.cursor.as_ref()
    }

    /// Positions given up because the reader fell more than one rotation
    /// behind (or the cursor was unreadable).
    pub fn lost_rotations(&self) -> u64 {
        self.lost_rotations
    }

    /// Times the current file was found shorter than the cursor and was
    /// restarted at 0.
    pub fn truncations(&self) -> u64 {
        self.truncations
    }
}

/// Opens `path` and reads the id from that handle. `None` if missing.
fn open_with_id(path: &std::path::Path) -> std::io::Result<Option<(File, Option<String>)>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let id = read_spool_id_from(&file)?;
    Ok(Some((file, id)))
}

fn positioned(mut file: File, offset: u64, len: u64, rotated: bool) -> std::io::Result<OpenSpool> {
    file.seek(SeekFrom::Start(offset))?;
    Ok(OpenSpool {
        file,
        offset,
        len,
        rotated,
    })
}

/// Tails the Agent's spool, following rotation and optionally persisting
/// its cursor. Unlike `LineTailer` it never advances past a partial last
/// line (it re-reads it next poll), so the cursor is always at a line
/// boundary and safe to persist.
pub struct SpoolTailer {
    reader: SpoolReader,
    cursor_path: Option<PathBuf>,
    /// The cursor last stored, so an idle poll loop does not rewrite it.
    committed: Mutex<Option<SpoolCursor>>,
    /// Most bytes one [`SpoolTailer::poll`] reads, across `.1` and the
    /// current file together.
    max_bytes: u64,
    /// Inside a line longer than `max_bytes`: drop bytes up to its `\n`.
    discarding: bool,
    oversized_lines: u64,
}

/// Default [`SpoolTailer`] per-poll read cap; the same as the forwarder's
/// per-batch byte cap.
pub const DEFAULT_POLL_MAX_BYTES: u64 = 4 * 1024 * 1024;

impl SpoolTailer {
    /// Loads the cursor from `cursor_path` when given; `None` keeps the
    /// position in memory only (begins the current file at 0).
    pub fn new(spool: impl Into<PathBuf>, cursor_path: Option<PathBuf>) -> Self {
        let load = match &cursor_path {
            Some(path) => SpoolCursor::load(path),
            None => CursorLoad::Missing,
        };
        let committed = match &load {
            CursorLoad::Loaded(cursor) => Some(cursor.clone()),
            _ => None,
        };
        Self {
            reader: SpoolReader::new(spool, load),
            cursor_path,
            committed: Mutex::new(committed),
            max_bytes: DEFAULT_POLL_MAX_BYTES,
            discarding: false,
            oversized_lines: 0,
        }
    }

    /// Overrides the per-poll read cap ([`DEFAULT_POLL_MAX_BYTES`]); a
    /// line longer than it is skipped and counted. At least 1.
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes.max(1);
        self
    }

    /// Lines skipped because they were longer than the per-poll cap.
    pub fn oversized_lines(&self) -> u64 {
        self.oversized_lines
    }

    /// Complete new lines (header lines dropped). Empty, not an error, if
    /// the spool does not exist yet or has not grown. Reads at most the
    /// length measured on the handle, so a concurrent append is never cut.
    /// After a rotation the rest of `<spool>.1` comes first, then the new
    /// file from 0, in this poll or the next.
    ///
    /// One poll reads at most `max_bytes` in total (`.1` and the current
    /// file together); the rest comes in later polls. A line longer than
    /// that is skipped (counted in [`SpoolTailer::oversized_lines`]) rather
    /// than stalling the tailer.
    pub fn poll(&mut self) -> std::io::Result<Vec<String>> {
        let mut out = Vec::new();
        let mut budget = self.max_bytes;
        // At most: the rest of `.1`, then the current file.
        for _ in 0..3 {
            if budget == 0 {
                break;
            }
            let Some(mut open) = self.reader.open()? else {
                break;
            };
            let remaining = open.len - open.offset;
            let want = remaining.min(budget);
            let capped = want < remaining;
            budget -= want;
            let mut buf = Vec::new();
            (&mut open.file).take(want).read_to_end(&mut buf)?;

            // Finish discarding an over-cap line first.
            let mut start = 0;
            if self.discarding {
                match buf.iter().position(|b| *b == b'\n') {
                    Some(nl) => {
                        start = nl + 1;
                        self.discarding = false;
                    }
                    None => start = buf.len(),
                }
            }
            let body = &buf[start..];
            let complete = match body.iter().rposition(|b| *b == b'\n') {
                Some(last_nl) => last_nl + 1,
                None => 0,
            };
            let consumed = if !self.discarding
                && complete == 0
                && capped
                && start == 0
                && want == self.max_bytes
            {
                // A whole cap's window from a line start holds no `\n`.
                self.oversized_lines += 1;
                self.discarding = true;
                buf.len()
            } else {
                // `.1` read to its end will never grow: take its torn tail.
                let body_consumed = if open.rotated && !capped {
                    body.len()
                } else {
                    complete
                };
                for line in body[..body_consumed].split(|b| *b == b'\n') {
                    if line.is_empty() || is_header_line(line) {
                        continue;
                    }
                    out.push(String::from_utf8_lossy(line).into_owned());
                }
                start + body_consumed
            };
            self.reader.advance(consumed as u64);
            if !open.rotated || capped {
                break;
            }
            // `.1` is finished; whatever it ended in, the next file starts
            // on a line boundary.
            self.discarding = false;
        }
        Ok(out)
    }

    /// Stores the cursor in `cursor_path` (if any) when it moved since the
    /// last commit.
    pub fn commit(&self) -> std::io::Result<()> {
        let (Some(path), Some(cursor)) = (&self.cursor_path, self.reader.cursor()) else {
            return Ok(());
        };
        let mut committed = self.committed.lock().unwrap_or_else(|e| e.into_inner());
        if committed.as_ref() == Some(cursor) {
            return Ok(());
        }
        cursor.store(path)?;
        *committed = Some(cursor.clone());
        Ok(())
    }

    /// See [`SpoolReader::lost_rotations`].
    pub fn lost_rotations(&self) -> u64 {
        self.reader.lost_rotations()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spool::{header_line, rotated_path};
    use std::io::Write;
    use std::path::Path;

    const ID_A: &str = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const ID_B: &str = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";
    const ID_C: &str = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d";

    fn lines(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn write_spool(path: &Path, id: Option<&str>, events: &[&str]) {
        let mut text = id.map(header_line).unwrap_or_default();
        for e in events {
            text.push_str(e);
            text.push('\n');
        }
        std::fs::write(path, text).unwrap();
    }

    fn append(path: &Path, events: &[&str]) {
        let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        for e in events {
            writeln!(f, "{e}").unwrap();
        }
    }

    /// Rotates exactly as `SpoolFileSink` does (osiris-bus, which depends
    /// on this crate, so it cannot be used here): a headered `<spool>.tmp`,
    /// then `<spool>` → `<spool>.1`, then `<spool>.tmp` → `<spool>`.
    fn rotate(spool: &Path, new_id: &str, events: &[&str]) {
        let mut tmp = spool.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        write_spool(&tmp, Some(new_id), events);
        std::fs::rename(spool, rotated_path(spool)).unwrap();
        std::fs::rename(&tmp, spool).unwrap();
    }

    /// Polls until nothing new comes back (at most a few times).
    fn drain(tailer: &mut SpoolTailer) -> Vec<String> {
        let mut out = Vec::new();
        for _ in 0..5 {
            out.extend(tailer.poll().unwrap());
        }
        out
    }

    /// Bytes of spool the lines of one poll cover (each plus its `\n`).
    fn line_bytes(polled: &[String]) -> u64 {
        polled.iter().map(|l| l.len() as u64 + 1).sum()
    }

    fn numbered(prefix: &str, n: usize) -> Vec<String> {
        (0..n).map(|i| format!("{prefix}{i:02}")).collect()
    }

    #[test]
    fn tailer_caps_one_poll_and_returns_the_rest_later() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        let all = numbered("e", 20); // 4 bytes per line with its `\n`
        let refs: Vec<&str> = all.iter().map(String::as_str).collect();
        write_spool(&spool, None, &refs);
        let mut tailer = SpoolTailer::new(&spool, None).with_max_bytes(10);

        let mut seen = Vec::new();
        for _ in 0..30 {
            let polled = tailer.poll().unwrap();
            assert!(line_bytes(&polled) <= 10, "poll over the cap: {polled:?}");
            seen.extend(polled);
        }
        assert_eq!(seen, all, "in order, no loss, no duplicates");
        assert_eq!(tailer.oversized_lines(), 0);
    }

    #[test]
    fn tailer_cap_spans_rotated_and_current_in_total() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write_spool(&spool, Some(ID_A), &[]);
        let mut tailer = SpoolTailer::new(&spool, None).with_max_bytes(100);
        assert!(tailer.poll().unwrap().is_empty());

        let old = numbered("a", 10);
        let new = numbered("b", 10);
        append(&spool, &old.iter().map(String::as_str).collect::<Vec<_>>());
        rotate(
            &spool,
            ID_B,
            &new.iter().map(String::as_str).collect::<Vec<_>>(),
        );

        // `.1` holds 40 event bytes, the new file a 54-byte header and 40
        // event bytes: more than one cap's worth in total.
        let first = tailer.poll().unwrap();
        assert!(
            first.len() < 20,
            "one poll took both whole files: {first:?}"
        );
        let mut seen = first;
        for _ in 0..10 {
            seen.extend(tailer.poll().unwrap());
        }
        let expected: Vec<String> = old.into_iter().chain(new).collect();
        assert_eq!(seen, expected);
    }

    #[test]
    fn tailer_skips_an_over_cap_line_without_stalling() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        let huge = "x".repeat(25);
        write_spool(&spool, Some(ID_A), &["short", &huge, "after"]);
        let mut tailer = SpoolTailer::new(&spool, None).with_max_bytes(10);
        // The 54-byte header itself is over this cap too; it is skipped the
        // same way (and is dropped anyway).
        let seen = (0..30)
            .flat_map(|_| tailer.poll().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(seen, lines(&["short", "after"]));
        assert_eq!(tailer.oversized_lines(), 2, "the header and the huge line");

        append(&spool, &["later"]);
        assert_eq!(drain(&mut tailer), lines(&["later"]));
    }

    #[test]
    fn tailer_skips_header_lines() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write_spool(&spool, Some(ID_A), &["e1", "e2"]);
        let mut tailer = SpoolTailer::new(&spool, None);
        assert_eq!(tailer.poll().unwrap(), lines(&["e1", "e2"]));
        assert_eq!(tailer.lost_rotations(), 0);
    }

    #[test]
    fn tailer_resumes_from_persisted_cursor_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        let cursor = dir.path().join("spool.offset");
        write_spool(&spool, Some(ID_A), &["e1", "e2", "e3"]);

        let mut tailer = SpoolTailer::new(&spool, Some(cursor.clone()));
        assert_eq!(tailer.poll().unwrap(), lines(&["e1", "e2", "e3"]));
        tailer.commit().unwrap();
        drop(tailer);

        append(&spool, &["e4", "e5"]);
        let mut tailer = SpoolTailer::new(&spool, Some(cursor));
        assert_eq!(drain(&mut tailer), lines(&["e4", "e5"]));
        assert_eq!(tailer.lost_rotations(), 0);
    }

    #[test]
    fn tailer_finishes_rotated_file_before_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write_spool(&spool, Some(ID_A), &["a1"]);
        let mut tailer = SpoolTailer::new(&spool, None);
        assert_eq!(tailer.poll().unwrap(), lines(&["a1"]));

        append(&spool, &["a2", "a3"]);
        rotate(&spool, ID_B, &["b1"]);
        append(&spool, &["b2"]);

        assert_eq!(drain(&mut tailer), lines(&["a2", "a3", "b1", "b2"]));
        append(&spool, &["b3"]);
        assert_eq!(drain(&mut tailer), lines(&["b3"]));
        assert_eq!(tailer.lost_rotations(), 0);
    }

    #[test]
    fn tailer_follows_rotation_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        let cursor = dir.path().join("spool.offset");
        write_spool(&spool, Some(ID_A), &["a1"]);
        let mut tailer = SpoolTailer::new(&spool, Some(cursor.clone()));
        assert_eq!(tailer.poll().unwrap(), lines(&["a1"]));
        tailer.commit().unwrap();
        drop(tailer);

        append(&spool, &["a2"]);
        rotate(&spool, ID_B, &["b1"]);
        let mut tailer = SpoolTailer::new(&spool, Some(cursor));
        assert_eq!(drain(&mut tailer), lines(&["a2", "b1"]));
        assert_eq!(tailer.lost_rotations(), 0);
    }

    #[test]
    fn tailer_waits_for_the_new_file_between_the_agents_renames() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write_spool(&spool, Some(ID_A), &["a1"]);
        let mut tailer = SpoolTailer::new(&spool, None);
        assert_eq!(tailer.poll().unwrap(), lines(&["a1"]));

        append(&spool, &["a2"]);
        std::fs::rename(&spool, rotated_path(&spool)).unwrap();
        assert_eq!(drain(&mut tailer), lines(&["a2"]));
        write_spool(&spool, Some(ID_B), &["b1"]);
        assert_eq!(drain(&mut tailer), lines(&["b1"]));
        assert_eq!(tailer.lost_rotations(), 0);
    }

    #[test]
    fn tailer_counts_lost_rotation_when_two_rotations_behind() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write_spool(&spool, Some(ID_A), &["a1"]);
        let mut tailer = SpoolTailer::new(&spool, None);
        assert_eq!(tailer.poll().unwrap(), lines(&["a1"]));

        append(&spool, &["a2"]);
        rotate(&spool, ID_B, &["b1"]);
        rotate(&spool, ID_C, &["c1"]);

        assert_eq!(drain(&mut tailer), lines(&["c1"]));
        assert_eq!(tailer.lost_rotations(), 1);
    }

    #[test]
    fn tailer_counts_a_garbled_cursor_as_lost() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        let cursor = dir.path().join("spool.offset");
        write_spool(&spool, Some(ID_A), &["a1"]);
        std::fs::write(&cursor, "not a cursor at all").unwrap();
        let mut tailer = SpoolTailer::new(&spool, Some(cursor));
        assert_eq!(tailer.lost_rotations(), 1);
        assert_eq!(drain(&mut tailer), lines(&["a1"]));
    }

    #[test]
    fn tailer_does_not_count_a_legacy_zero_cursor_as_lost() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        let cursor = dir.path().join("spool.offset");
        write_spool(&spool, Some(ID_A), &["a1"]);
        std::fs::write(&cursor, "0").unwrap();
        let mut tailer = SpoolTailer::new(&spool, Some(cursor));
        assert_eq!(drain(&mut tailer), lines(&["a1"]));
        assert_eq!(tailer.lost_rotations(), 0);
    }

    #[test]
    fn tailer_in_memory_mode_without_cursor_path() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write_spool(&spool, None, &["e1"]);
        let mut tailer = SpoolTailer::new(&spool, None);
        assert_eq!(tailer.poll().unwrap(), lines(&["e1"]));
        tailer.commit().unwrap();
        append(&spool, &["e2"]);
        assert_eq!(tailer.poll().unwrap(), lines(&["e2"]));
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("spool.ndjson")]);
    }

    #[test]
    fn tailer_restarts_on_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write_spool(&spool, None, &["line one", "line two", "line three"]);
        let mut tailer = SpoolTailer::new(&spool, None);
        assert_eq!(tailer.poll().unwrap().len(), 3);
        write_spool(&spool, None, &["fresh"]);
        assert_eq!(tailer.poll().unwrap(), lines(&["fresh"]));
        append(&spool, &["fresh two"]);
        assert_eq!(tailer.poll().unwrap(), lines(&["fresh two"]));
    }

    #[test]
    fn tailer_buffers_a_partial_line_and_commits_only_whole_lines() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        let cursor = dir.path().join("spool.offset");
        write_spool(&spool, Some(ID_A), &["e1"]);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&spool)
            .unwrap()
            .write_all(b"par")
            .unwrap();
        let mut tailer = SpoolTailer::new(&spool, Some(cursor.clone()));
        assert_eq!(tailer.poll().unwrap(), lines(&["e1"]));
        tailer.commit().unwrap();
        drop(tailer);

        append(&spool, &["tial"]);
        let mut tailer = SpoolTailer::new(&spool, Some(cursor));
        assert_eq!(drain(&mut tailer), lines(&["partial"]));
    }

    #[test]
    fn tailer_ends_a_rotated_file_with_a_partial_last_line() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write_spool(&spool, Some(ID_A), &["a1"]);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&spool)
            .unwrap()
            .write_all(b"torn")
            .unwrap();
        let mut tailer = SpoolTailer::new(&spool, None);
        assert_eq!(tailer.poll().unwrap(), lines(&["a1"]));
        rotate(&spool, ID_B, &["b1"]);
        assert_eq!(drain(&mut tailer), lines(&["torn", "b1"]));
    }

    #[test]
    fn reader_never_reads_a_new_file_at_the_old_offset() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write_spool(&spool, Some(ID_A), &["a1", "a2"]);
        let mut reader = SpoolReader::new(&spool, CursorLoad::Missing);
        let open = reader.open().unwrap().unwrap();
        assert!(!open.rotated);
        reader.advance(open.len);
        let cursor = reader.cursor().unwrap().clone();
        assert_eq!(cursor.id.as_deref(), Some(ID_A));

        // A new current file much longer than the old offset: the reader
        // must finish `.1` (nothing left) and then start it at 0.
        rotate(&spool, ID_B, &["b1", "b2", "b3", "b4", "b5", "b6"]);
        let open = reader.open().unwrap().unwrap();
        assert!(!open.rotated);
        assert_eq!(open.offset, 0);
        assert_eq!(reader.cursor().unwrap().id.as_deref(), Some(ID_B));
    }
}
