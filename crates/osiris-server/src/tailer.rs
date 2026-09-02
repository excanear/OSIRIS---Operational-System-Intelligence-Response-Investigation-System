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
        file.read_to_string(&mut buf)?;
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
}
