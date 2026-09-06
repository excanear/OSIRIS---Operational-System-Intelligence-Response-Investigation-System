use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

/// Tails a growing NDJSON file, returning complete new lines since the
/// last poll. Deliberately duplicated (not shared) with
/// osiris-sensors-process's AuditLogTailer: osiris-server must never
/// depend on osiris-sensors-process (ARCHITECTURE.md §27, enforced by
/// tools/check-dep-graph.sh), and extracting a shared osiris-kernel crate
/// for two ~20-line tailers is deferred (plan Global Constraints #7).
pub struct SpoolTailer {
    path: PathBuf,
    offset: u64,
    partial: String,
}

impl SpoolTailer {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            offset: 0,
            partial: String::new(),
        }
    }

    pub fn poll(&mut self) -> std::io::Result<Vec<String>> {
        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let len = file.metadata()?.len();
        if len < self.offset {
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
            lines.pop();
        }
        Ok(lines.into_iter().filter(|l| !l.is_empty()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn returns_new_lines_across_polls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        std::fs::write(&path, "{\"a\":1}\n").unwrap();

        let mut tailer = SpoolTailer::new(&path);
        assert_eq!(tailer.poll().unwrap(), vec!["{\"a\":1}".to_string()]);

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "{{\"a\":2}}").unwrap();

        assert_eq!(tailer.poll().unwrap(), vec!["{\"a\":2}".to_string()]);
    }

    #[test]
    fn returns_empty_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut tailer = SpoolTailer::new(dir.path().join("missing.ndjson"));
        assert_eq!(tailer.poll().unwrap(), Vec::<String>::new());
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
        let path = dir.path().join("spool.ndjson");
        std::fs::write(&path, "").unwrap();

        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&writer_path)
                .unwrap();
            for i in 0..500 {
                writeln!(file, "{{\"seq\":{i}}}").unwrap();
                file.flush().unwrap();
            }
        });

        let mut tailer = SpoolTailer::new(&path);
        let mut seen: Vec<u64> = Vec::new();
        for _ in 0..2000 {
            for line in tailer.poll().unwrap() {
                let seq: u64 = line
                    .trim()
                    .strip_prefix("{\"seq\":")
                    .and_then(|s| s.strip_suffix('}'))
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
                .strip_prefix("{\"seq\":")
                .and_then(|s| s.strip_suffix('}'))
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
