//! Rotating NDJSON/CSV file exporter.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::config::{FileConfig, FileFormat};
use crate::error::{ConfigError, ExportError};
use crate::exporter::{ExportOutcome, Exporter};
use crate::format::{csv_header, csv_row, ndjson_line};
use crate::record::{ExportRecord, Stream};

struct State {
    file: Option<File>,
    size: u64,
}

struct Params {
    path: PathBuf,
    format: FileFormat,
    max_bytes: u64,
    max_files: u32,
    csv_stream: Stream,
    #[cfg(test)]
    fail_open: std::sync::atomic::AtomicBool,
}

pub struct FileExporter {
    name: String,
    include_raw: bool,
    params: Arc<Params>,
    state: Arc<Mutex<State>>,
}

fn open(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn suffixed(path: &Path, n: u32) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

fn remove_if_exists(p: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(p) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// `path.(N-1)` -> `path.N` ... `path` -> `path.1`; the oldest is deleted.
/// The oldest target is removed first because renaming over a file fails on
/// Windows.
fn rotate(path: &Path, max_files: u32) -> std::io::Result<()> {
    if max_files == 0 {
        return remove_if_exists(path);
    }
    remove_if_exists(&suffixed(path, max_files))?;
    for i in (1..max_files).rev() {
        let from = suffixed(path, i);
        if from.exists() {
            std::fs::rename(&from, suffixed(path, i + 1))?;
        }
    }
    std::fs::rename(path, suffixed(path, 1))
}

impl Params {
    fn open_file(&self) -> std::io::Result<File> {
        #[cfg(test)]
        if self.fail_open.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }
        open(&self.path)
    }

    /// Reopen the file if a previous rotation left it closed. A fresh (empty)
    /// file gets the CSV header.
    fn ensure_open<'a>(&self, st: &'a mut State) -> std::io::Result<&'a mut File> {
        if st.file.is_none() {
            let mut f = self.open_file()?;
            let mut size = f.metadata()?.len();
            if size == 0 && self.format == FileFormat::Csv {
                let h = csv_header(self.csv_stream);
                f.write_all(h.as_bytes())?;
                size = h.len() as u64;
            }
            st.file = Some(f);
            st.size = size;
        }
        Ok(st.file.as_mut().expect("file just opened"))
    }

    fn write_batch(&self, st: &mut State, lines: &[String]) -> std::io::Result<()> {
        self.ensure_open(st)?;
        let mut buf: Vec<u8> = Vec::new();
        for line in lines {
            let len = line.len() as u64;
            if st.size + buf.len() as u64 > 0 && st.size + buf.len() as u64 + len > self.max_bytes {
                self.ensure_open(st)?.write_all(&buf)?;
                buf.clear();
                // Close the handle before renaming (required on Windows). If
                // anything below fails the exporter stays closed and the next
                // export retries the reopen (and reports Transient until it works).
                st.file = None;
                rotate(&self.path, self.max_files)?;
                self.ensure_open(st)?;
            }
            buf.extend_from_slice(line.as_bytes());
        }
        let file = self.ensure_open(st)?;
        file.write_all(&buf)?;
        file.flush()?;
        st.size += buf.len() as u64;
        Ok(())
    }
}

impl FileExporter {
    pub fn new(
        name: &str,
        cfg: &FileConfig,
        include_raw: bool,
        stream_for_csv: Option<Stream>,
    ) -> Result<Self, ConfigError> {
        let fail = |what: &str, e: std::io::Error| {
            ConfigError::new(
                name,
                format!("{what} `{}`: {}", cfg.path.display(), e.kind()),
            )
        };
        if let Some(parent) = cfg.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| fail("cannot create dir for", e))?;
            }
        }
        let csv_stream = stream_for_csv.unwrap_or(Stream::Events);
        let mut file = open(&cfg.path).map_err(|e| fail("cannot open", e))?;
        let mut size = file.metadata().map_err(|e| fail("cannot stat", e))?.len();
        if size == 0 && cfg.format == FileFormat::Csv {
            let h = csv_header(csv_stream);
            file.write_all(h.as_bytes())
                .map_err(|e| fail("cannot write", e))?;
            size = h.len() as u64;
        }
        Ok(Self {
            name: name.to_string(),
            include_raw,
            params: Arc::new(Params {
                path: cfg.path.clone(),
                format: cfg.format,
                max_bytes: cfg.max_bytes,
                max_files: cfg.max_files,
                csv_stream,
                #[cfg(test)]
                fail_open: std::sync::atomic::AtomicBool::new(false),
            }),
            state: Arc::new(Mutex::new(State {
                file: Some(file),
                size,
            })),
        })
    }
}

#[async_trait]
impl Exporter for FileExporter {
    fn name(&self) -> &str {
        &self.name
    }

    async fn export(&self, batch: &[Arc<ExportRecord>]) -> Result<ExportOutcome, ExportError> {
        let lines: Vec<String> = batch
            .iter()
            .map(|r| match self.params.format {
                FileFormat::Ndjson => {
                    let mut l = ndjson_line(r, self.include_raw);
                    l.push('\n');
                    l
                }
                FileFormat::Csv => csv_row(r),
            })
            .collect();
        let mut guard = self.state.clone().lock_owned().await;
        let params = self.params.clone();
        tokio::task::spawn_blocking(move || params.write_batch(&mut guard, &lines))
            .await
            .map_err(|_| ExportError::Transient("file writer task failed".into()))?
            .map_err(|e| {
                ExportError::Transient(format!(
                    "file write to `{}` failed: {}",
                    self.params.path.display(),
                    e.kind()
                ))
            })?;
        Ok(ExportOutcome::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FileFormat;
    use crate::exporter::Exporter;
    use crate::transport::testutil::event;

    fn cfg(path: PathBuf, format: FileFormat, max_bytes: u64, max_files: u32) -> FileConfig {
        FileConfig {
            path,
            format,
            max_bytes,
            max_files,
        }
    }

    #[tokio::test]
    async fn file_ndjson_appends_one_line_per_record() {
        let dir = tempfile_dir("nd");
        let path = dir.join("out.ndjson");
        let ex = FileExporter::new(
            "f",
            &cfg(path.clone(), FileFormat::Ndjson, 1 << 20, 3),
            false,
            None,
        )
        .unwrap();
        ex.export(&[event(1), event(2)]).await.unwrap();
        ex.export(&[event(3)]).await.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        for l in lines {
            serde_json::from_str::<serde_json::Value>(l).unwrap();
        }
    }

    #[tokio::test]
    async fn file_csv_writes_header_once_per_file() {
        let dir = tempfile_dir("csv");
        let path = dir.join("out.csv");
        let ex = FileExporter::new(
            "f",
            &cfg(path.clone(), FileFormat::Csv, 1 << 20, 3),
            false,
            Some(Stream::Events),
        )
        .unwrap();
        ex.export(&[event(1)]).await.unwrap();
        ex.export(&[event(2)]).await.unwrap();
        drop(ex);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches("timestamp,event_id").count(), 1);
        assert_eq!(text.lines().count(), 3);
        // A reopened exporter appends without a second header.
        let ex = FileExporter::new(
            "f",
            &cfg(path.clone(), FileFormat::Csv, 1 << 20, 3),
            false,
            Some(Stream::Events),
        )
        .unwrap();
        ex.export(&[event(3)]).await.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches("timestamp,event_id").count(), 1);
        assert_eq!(text.lines().count(), 4);
    }

    #[tokio::test]
    async fn file_rotates_at_max_bytes_and_keeps_max_files() {
        let dir = tempfile_dir("rot");
        let path = dir.join("out.ndjson");
        let ex = FileExporter::new(
            "f",
            &cfg(path.clone(), FileFormat::Ndjson, 200, 2),
            false,
            None,
        )
        .unwrap();
        for i in 0..12u8 {
            ex.export(&[event(i)]).await.unwrap();
        }
        let sibling = |n: u32| PathBuf::from(format!("{}.{n}", path.display()));
        assert!(path.exists());
        assert!(sibling(1).exists());
        assert!(sibling(2).exists());
        assert!(!sibling(3).exists());
        // Newest data is in `path`, older in higher suffixes.
        let first = |p: &PathBuf| std::fs::read_to_string(p).unwrap();
        assert!(first(&path).contains("000000000011"));
        assert!(!first(&sibling(2)).contains("000000000011"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_is_created_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile_dir("mode");
        let path = dir.join("out.ndjson");
        let ex = FileExporter::new(
            "f",
            &cfg(path.clone(), FileFormat::Ndjson, 1 << 20, 3),
            false,
            None,
        )
        .unwrap();
        ex.export(&[event(1)]).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[tokio::test]
    async fn failed_reopen_after_rotation_is_transient_until_the_path_is_writable() {
        use std::sync::atomic::Ordering;
        let dir = tempfile_dir("reopen");
        let path = dir.join("out.ndjson");
        let ex = FileExporter::new(
            "f",
            &cfg(path.clone(), FileFormat::Ndjson, 200, 2),
            false,
            None,
        )
        .unwrap();
        ex.export(&[event(1)]).await.unwrap();
        ex.params.fail_open.store(true, Ordering::SeqCst);
        // The next write rotates, then the reopen fails.
        let e = ex.export(&[event(2)]).await.unwrap_err();
        assert!(matches!(e, ExportError::Transient(_)), "{e}");
        // Still failing, never silently Ok.
        let e = ex.export(&[event(3)]).await.unwrap_err();
        assert!(matches!(e, ExportError::Transient(_)), "{e}");
        ex.params.fail_open.store(false, Ordering::SeqCst);
        ex.export(&[event(4)]).await.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("000000000004"), "{text}");
    }

    fn tempfile_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "osiris-export-{tag}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
