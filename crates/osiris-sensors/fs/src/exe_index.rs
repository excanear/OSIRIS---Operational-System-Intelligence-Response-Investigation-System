//! Executable identity → path index for the eBPF fs backend.
//!
//! An fs record carries the actor's kernel-verified executable identity
//! `(st_dev, st_ino)`, but the path normally comes from `/proc/<pid>/exe`,
//! which is gone when a short-lived process (`bash -c 'echo x > f'`) has
//! exited before the reader sees its record. This index maps identities to
//! canonical paths so such records still get an `exe_path`:
//!
//! - it is seeded by scanning the standard binary directories (first insert
//!   wins, so on a merged-/usr host `/usr/bin/bash` beats `/bin/bash`, as
//!   `/proc/<pid>/exe` would report);
//! - it learns every identity → path pair that `resolve_exe` resolves;
//! - on a miss it rescans, at most once per [`RESCAN_INTERVAL`], so a newly
//!   installed or upgraded binary is found later without per-event scans;
//! - it holds at most [`EXE_INDEX_CAPACITY`] entries; once full it stops
//!   inserting (entries are never evicted, and nothing grows unboundedly).
//!
//! Unknown identities stay `""`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use osiris_ebpf::{resolve_exe, ExeIdentity, FsEvent};

/// Directories scanned for executables, in priority order.
pub const EXE_SCAN_DIRS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

/// Maximum number of identities held; further inserts are ignored.
pub const EXE_INDEX_CAPACITY: usize = 65_536;

/// Minimum time between two rescans triggered by misses.
pub const RESCAN_INTERVAL: Duration = Duration::from_secs(60);

pub struct ExeIndex {
    map: HashMap<(u64, u64), String>,
    dirs: Vec<PathBuf>,
    capacity: usize,
    rescan_interval: Duration,
    last_scan: Option<Instant>,
}

impl ExeIndex {
    /// An index that scans `dirs` (in order) and holds at most `capacity`
    /// entries. Nothing is scanned until [`ExeIndex::rescan`] or a miss.
    pub fn new(dirs: Vec<PathBuf>, capacity: usize, rescan_interval: Duration) -> Self {
        Self {
            map: HashMap::new(),
            dirs,
            capacity,
            rescan_interval,
            last_scan: None,
        }
    }

    /// The production index over [`EXE_SCAN_DIRS`], already scanned.
    pub fn with_default_dirs() -> Self {
        let mut index = Self::new(
            EXE_SCAN_DIRS.iter().map(PathBuf::from).collect(),
            EXE_INDEX_CAPACITY,
            RESCAN_INTERVAL,
        );
        index.rescan(Instant::now());
        index
    }

    /// An index that never scans (pure conversion, tests).
    pub fn empty() -> Self {
        Self::new(vec![], EXE_INDEX_CAPACITY, RESCAN_INTERVAL)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Record `identity → path`. The first path for an identity wins; a
    /// full index ignores new identities.
    pub fn insert(&mut self, identity: ExeIdentity, path: String) {
        if self.map.len() >= self.capacity {
            return;
        }
        self.map.entry((identity.dev, identity.ino)).or_insert(path);
    }

    /// Path for `identity`. On a miss, rescans the directories if the last
    /// scan is at least the rescan interval old (`now` is passed in so the
    /// rate limit is testable), then looks again.
    pub fn lookup(&mut self, identity: ExeIdentity, now: Instant) -> Option<String> {
        let key = (identity.dev, identity.ino);
        if let Some(p) = self.map.get(&key) {
            return Some(p.clone());
        }
        let due = self
            .last_scan
            .is_none_or(|t| now.saturating_duration_since(t) >= self.rescan_interval);
        if due {
            self.rescan(now);
        }
        self.map.get(&key).cloned()
    }

    /// Scan every directory, stat-ing (following symlinks) its regular
    /// files and adding `(st_dev, st_ino) → canonical path`.
    pub fn rescan(&mut self, now: Instant) {
        self.last_scan = Some(now);
        for dir in self.dirs.clone() {
            self.scan_dir(&dir);
        }
    }

    #[cfg(unix)]
    fn scan_dir(&mut self, dir: &Path) {
        use std::os::unix::fs::MetadataExt;
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        // Sorted, so which of two names for one inode wins is deterministic.
        let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
        paths.sort();
        for path in paths {
            if self.map.len() >= self.capacity {
                return;
            }
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let Ok(canonical) = std::fs::canonicalize(&path) else {
                continue;
            };
            self.insert(
                ExeIdentity {
                    dev: meta.dev(),
                    ino: meta.ino(),
                },
                canonical.to_string_lossy().into_owned(),
            );
        }
    }

    #[cfg(not(unix))]
    fn scan_dir(&mut self, _dir: &Path) {}

    /// `exe_path` for a record: the `/proc/<pid>/exe` link when
    /// [`resolve_exe`] ties it to the record (also learned here), else the
    /// path indexed for the record's kernel exe identity, else `""`.
    pub fn exe_path(&mut self, e: &FsEvent, proc_root: &Path) -> String {
        if let Some(path) = resolve_exe(proc_root, e.pid, e.exe, &e.comm) {
            if let Some(identity) = e.exe {
                self.insert(identity, path.clone());
            }
            return path;
        }
        e.exe
            .and_then(|identity| self.lookup(identity, Instant::now()))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_ebpf::FsKind;

    fn id(dev: u64, ino: u64) -> ExeIdentity {
        ExeIdentity { dev, ino }
    }

    fn index(capacity: usize) -> ExeIndex {
        ExeIndex::new(vec![], capacity, Duration::from_secs(60))
    }

    fn event(exe: Option<ExeIdentity>) -> FsEvent {
        FsEvent {
            kind: FsKind::Create,
            // No such pid under the fixture root.
            pid: 4242,
            ppid: 1,
            uid: 0,
            ret: 0,
            ktime_ns: 1,
            comm: "bash".to_string(),
            exe,
            inode: None,
            path: b"/var/www/a.php".to_vec(),
            path_truncated: false,
            old_path: None,
            old_path_truncated: false,
        }
    }

    #[test]
    fn insert_and_lookup_first_insert_wins() {
        let mut ix = index(10);
        ix.insert(id(1, 2), "/usr/bin/bash".into());
        ix.insert(id(1, 2), "/bin/bash".into());
        assert_eq!(
            ix.lookup(id(1, 2), Instant::now()).as_deref(),
            Some("/usr/bin/bash")
        );
        assert_eq!(ix.lookup(id(9, 9), Instant::now()), None);
    }

    #[test]
    fn a_full_index_stops_inserting() {
        let mut ix = index(2);
        ix.insert(id(1, 1), "/a".into());
        ix.insert(id(1, 2), "/b".into());
        ix.insert(id(1, 3), "/c".into());
        assert_eq!(ix.len(), 2);
        assert_eq!(ix.lookup(id(1, 3), Instant::now()), None);
        assert_eq!(ix.lookup(id(1, 1), Instant::now()).as_deref(), Some("/a"));
    }

    #[test]
    fn unknown_identity_or_none_gives_empty_exe_path() {
        let root = tempfile::tempdir().unwrap();
        let mut ix = index(10);
        assert_eq!(ix.exe_path(&event(None), root.path()), "");
        assert_eq!(ix.exe_path(&event(Some(id(5, 5))), root.path()), "");
    }

    #[test]
    fn an_indexed_identity_resolves_when_proc_is_gone() {
        let root = tempfile::tempdir().unwrap();
        let mut ix = index(10);
        ix.insert(id(5, 5), "/usr/bin/bash".into());
        assert_eq!(
            ix.exe_path(&event(Some(id(5, 5))), root.path()),
            "/usr/bin/bash"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_resolve_exe_hit_takes_precedence_and_is_learned() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("real-bin");
        std::fs::write(&target, b"x").unwrap();
        let meta = std::fs::metadata(&target).unwrap();
        let identity = id(meta.dev(), meta.ino());
        let pid_dir = root.path().join("4242");
        std::fs::create_dir(&pid_dir).unwrap();
        std::os::unix::fs::symlink(&target, pid_dir.join("exe")).unwrap();

        let mut ix = index(10);
        ix.insert(identity, "/stale/other".into());
        // Link matches the identity: the link wins over the index...
        let got = ix.exe_path(&event(Some(identity)), root.path());
        assert_eq!(got, target.to_string_lossy());
        // ...and an unseen identity is learned from the hit.
        let mut fresh = index(10);
        fresh.exe_path(&event(Some(identity)), root.path());
        assert_eq!(
            fresh.lookup(identity, Instant::now()).as_deref(),
            Some(&*target.to_string_lossy())
        );
    }

    #[cfg(unix)]
    #[test]
    fn scanning_indexes_regular_files_first_dir_wins_and_rescans_are_rate_limited() {
        use std::os::unix::fs::MetadataExt;
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        std::fs::write(a.path().join("tool"), b"x").unwrap();
        std::fs::create_dir(a.path().join("subdir")).unwrap();
        // b/alias is a symlink to the same inode as a/tool.
        std::os::unix::fs::symlink(a.path().join("tool"), b.path().join("alias")).unwrap();
        let meta = std::fs::metadata(a.path().join("tool")).unwrap();
        let identity = id(meta.dev(), meta.ino());
        let canonical_tool = std::fs::canonicalize(a.path().join("tool")).unwrap();

        let mut ix = ExeIndex::new(
            vec![a.path().to_path_buf(), b.path().to_path_buf()],
            100,
            Duration::from_secs(60),
        );
        let t0 = Instant::now();
        ix.rescan(t0);
        assert_eq!(ix.len(), 1, "only the regular file, once");
        assert_eq!(
            ix.lookup(identity, t0).as_deref(),
            Some(&*canonical_tool.to_string_lossy())
        );

        // A binary installed later is not found before the interval...
        std::fs::write(a.path().join("late"), b"yy").unwrap();
        let late = std::fs::metadata(a.path().join("late")).unwrap();
        let late_id = id(late.dev(), late.ino());
        assert_eq!(ix.lookup(late_id, t0 + Duration::from_secs(10)), None);
        // ...but is once it has passed.
        assert!(ix.lookup(late_id, t0 + Duration::from_secs(61)).is_some());
    }
}
