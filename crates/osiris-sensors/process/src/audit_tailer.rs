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
        Self { path: path.into(), offset: 0, partial: String::new() }
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
        file.read_to_string(&mut buf)?;
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

        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
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

        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        write!(file, " now complete\n").unwrap();

        assert_eq!(tailer.poll().unwrap(), vec!["partial now complete".to_string()]);
    }
}
