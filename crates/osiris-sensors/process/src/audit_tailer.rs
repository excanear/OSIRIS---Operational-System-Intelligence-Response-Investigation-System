use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

/// Tails a growing text file by tracking a byte offset, returning any
/// complete new lines since the last poll (buffering a trailing partial
/// line for the next call). Pure std::fs — no OS-specific API, so this
/// works identically on Linux (tailing a real auditd log) and on any dev
/// machine (tailing a fixture file in tests) — plan Global Constraints #2.
pub struct AuditLogTailer {
    path: PathBuf,
    offset: u64,
    partial: String,
}

impl AuditLogTailer {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            offset: 0,
            partial: String::new(),
        }
    }

    /// Returns any complete new lines appended to the file since the last
    /// call. Returns an empty Vec (not an error) if the file doesn't exist
    /// yet or hasn't grown — the sensor treats "no new lines" as normal.
    pub fn poll(&mut self) -> std::io::Result<Vec<String>> {
        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let len = file.metadata()?.len();
        if len < self.offset {
            // File was truncated/rotated — restart from the beginning.
            self.offset = 0;
            self.partial.clear();
        }
        if len == self.offset {
            return Ok(vec![]);
        }
        file.seek(SeekFrom::Start(self.offset))?;
        let mut buf = String::new();
        // Bound the read to exactly the measured length: read_to_string
        // reads to the *current* EOF, which can have grown past `len` if
        // the writer appended concurrently. Reading past `len` in one poll
        // risks capturing a mid-write partial line while still advancing
        // `self.offset` only to `len`, causing that event to be re-read
        // and corrupted (prefixed with stale partial data) on next poll.
        (&mut file)
            .take(len - self.offset)
            .read_to_string(&mut buf)?;
        self.offset = len;

        buf.insert_str(0, &self.partial);
        self.partial.clear();

        let mut lines: Vec<String> = buf.split('\n').map(|s| s.to_string()).collect();
        if !buf.ends_with('\n') {
            self.partial = lines.pop().unwrap_or_default();
        } else {
            lines.pop(); // trailing empty string after the last '\n'
        }
        Ok(lines.into_iter().filter(|l| !l.is_empty()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn returns_empty_when_file_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let mut tailer = AuditLogTailer::new(dir.path().join("missing.log"));
        assert_eq!(tailer.poll().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn returns_new_complete_lines_across_multiple_polls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "line one\nline two\n").unwrap();

        let mut tailer = AuditLogTailer::new(&path);
        let first = tailer.poll().unwrap();
        assert_eq!(first, vec!["line one".to_string(), "line two".to_string()]);

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "line three").unwrap();

        let second = tailer.poll().unwrap();
        assert_eq!(second, vec!["line three".to_string()]);
    }

    #[test]
    fn buffers_a_partial_trailing_line_until_it_completes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "complete line\npartial").unwrap();

        let mut tailer = AuditLogTailer::new(&path);
        assert_eq!(tailer.poll().unwrap(), vec!["complete line".to_string()]);

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, " now complete").unwrap();

        assert_eq!(
            tailer.poll().unwrap(),
            vec!["partial now complete".to_string()]
        );
    }

    #[test]
    fn restarts_from_zero_after_the_file_is_truncated_by_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "line one\nline two\nline three\n").unwrap();

        let mut tailer = AuditLogTailer::new(&path);
        let first = tailer.poll().unwrap();
        assert_eq!(
            first,
            vec![
                "line one".to_string(),
                "line two".to_string(),
                "line three".to_string()
            ]
        );

        // Simulate log rotation: auditd (or logrotate's copytruncate mode)
        // truncates the file in place rather than replacing the inode, so
        // the tracked byte offset now points past the end of the
        // (shorter) new content.
        std::fs::write(&path, "fresh line one\n").unwrap();

        let after_rotation = tailer.poll().unwrap();
        assert_eq!(
            after_rotation,
            vec!["fresh line one".to_string()],
            "post-rotation content must be read from offset 0, not lost or double-read"
        );

        // A further append keeps working normally from the new offset.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "fresh line two").unwrap();

        let after_append = tailer.poll().unwrap();
        assert_eq!(after_append, vec!["fresh line two".to_string()]);
    }

    /// Regression test for finding 1: a writer appending lines concurrently
    /// with poll() must never produce a corrupted/concatenated line. Before
    /// the fix, an unbounded `read_to_string` could read past the length
    /// measured by `metadata()`, while `self.offset` was rewound to that
    /// (smaller) measured length — causing the next poll to re-read and
    /// prepend stale partial data onto already-seen bytes, silently
    /// dropping the resulting unparseable line. Every line this test ever
    /// observes must be an intact, well-formed line from the writer.
    #[test]
    fn survives_concurrent_writer_without_corrupting_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();

        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&writer_path)
                .unwrap();
            for i in 0..500 {
                writeln!(file, "event seq={i}").unwrap();
                file.flush().unwrap();
            }
        });

        let mut tailer = AuditLogTailer::new(&path);
        let mut seen: Vec<u64> = Vec::new();
        for _ in 0..2000 {
            for line in tailer.poll().unwrap() {
                let seq: u64 = line
                    .trim()
                    .strip_prefix("event seq=")
                    .unwrap_or_else(|| panic!("corrupted line: {line:?}"))
                    .parse()
                    .unwrap_or_else(|_| panic!("corrupted line: {line:?}"));
                seen.push(seq);
            }
            if seen.len() >= 500 {
                break;
            }
        }
        writer.join().unwrap();
        // Drain anything left after the writer finished.
        for line in tailer.poll().unwrap() {
            let seq: u64 = line
                .trim()
                .strip_prefix("event seq=")
                .unwrap_or_else(|| panic!("corrupted line: {line:?}"))
                .parse()
                .unwrap_or_else(|_| panic!("corrupted line: {line:?}"));
            seen.push(seq);
        }

        // Every observed sequence number must be in strictly increasing
        // order with no duplicates and no gaps introduced by corruption.
        assert_eq!(seen, (0..seen.len() as u64).collect::<Vec<_>>());
        assert_eq!(seen.len(), 500, "must observe every line the writer sent");
    }
}
