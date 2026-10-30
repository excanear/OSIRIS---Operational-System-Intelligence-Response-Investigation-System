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

/// See [`ExeIndex`]: path → `(st_dev, st_ino)`.
type StatFn = Box<dyn Fn(&Path) -> Option<(u64, u64)> + Send>;

pub struct ExeIndex {
    map: HashMap<(u64, u64), String>,
    dirs: Vec<PathBuf>,
    capacity: usize,
    rescan_interval: Duration,
    last_scan: Option<Instant>,
    /// `(st_dev, st_ino)` of what a path points to (following symlinks);
    /// a seam so the verification logic is testable on every OS.
    stat: StatFn,
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
            stat: Box::new(stat_identity),
        }
    }

    /// Replace the stat function (tests).
    pub fn with_stat(
        mut self,
        stat: impl Fn(&Path) -> Option<(u64, u64)> + Send + 'static,
    ) -> Self {
        self.stat = Box::new(stat);
        self
    }

    /// The production index over [`EXE_SCAN_DIRS`], already scanned.
    pub fn with_default_dirs() -> Self {
        let mut index = Self::default_dirs_unscanned();
        index.rescan(Instant::now());
        index
    }

    /// The production index over [`EXE_SCAN_DIRS`], not scanned yet (the
    /// first miss scans).
    pub fn default_dirs_unscanned() -> Self {
        Self::new(
            EXE_SCAN_DIRS.iter().map(PathBuf::from).collect(),
            EXE_INDEX_CAPACITY,
            RESCAN_INTERVAL,
        )
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

    /// Record `identity → path`, for a pair the caller has already verified
    /// (scan results). The first path for an identity wins, unless the
    /// stored path no longer stats to that identity (stale: an inode
    /// reused after an upgrade), in which case it is replaced. A full index
    /// ignores new identities.
    pub fn insert(&mut self, identity: ExeIdentity, path: String) {
        let key = (identity.dev, identity.ino);
        match self.map.get(&key) {
            Some(old) if (self.stat)(Path::new(old)) == Some(key) => {}
            Some(_) => {
                self.map.insert(key, path);
            }
            None if self.map.len() >= self.capacity => {}
            None => {
                self.map.insert(key, path);
            }
        }
    }

    /// Learn `identity → path` only if `stat(path)` is exactly `identity`.
    /// Returns whether the pair was verified (and so inserted). A path found
    /// by a weaker rule (comm match) is never learned.
    pub fn learn(&mut self, identity: ExeIdentity, path: &str) -> bool {
        let verified = (self.stat)(Path::new(path)) == Some((identity.dev, identity.ino));
        if verified {
            self.insert(identity, path.to_string());
        }
        verified
    }

    /// Path for `identity`. A hit is re-verified: the stored path must still
    /// stat to the key, else the entry is evicted and treated as a miss. On
    /// a miss, rescans the directories if the last scan is at least the
    /// rescan interval old (`now` is passed in so the rate limit is
    /// testable), then looks again.
    pub fn lookup(&mut self, identity: ExeIdentity, now: Instant) -> Option<String> {
        let key = (identity.dev, identity.ino);
        if let Some(p) = self.map.get(&key) {
            if (self.stat)(Path::new(p)) == Some(key) {
                return Some(p.clone());
            }
            self.map.remove(&key);
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

    /// `exe_path` for a record:
    ///
    /// 1. the `/proc/<pid>/exe` link when [`resolve_exe`] ties it to the
    ///    record and the link's path (learned) or the proc link itself
    ///    stats to the record's identity;
    /// 2. the path indexed for the record's kernel exe identity, when the
    ///    link is missing or tied only by its comm (a later exec that kept
    ///    the comm, e.g. `/tmp/bash` exec'ing `/usr/bin/bash`, must not
    ///    lend the new image to the old record);
    /// 3. a comm-tied link, unless its path stats to a different inode on
    ///    the record identity's own device (then it is certainly another
    ///    file). A different device is no proof: btrfs and overlayfs
    ///    report a `st_dev` other than the kernel's, so there the link is
    ///    kept, as in 11b-1;
    /// 4. else `""`.
    pub fn exe_path(&mut self, e: &FsEvent, proc_root: &Path) -> String {
        let link = resolve_exe(proc_root, e.pid, e.exe, &e.comm);
        let Some(identity) = e.exe else {
            return link.unwrap_or_default();
        };
        if let Some(path) = &link {
            if self.learn(identity, path) {
                return path.clone();
            }
            // Tied by identity through the proc link itself, though the
            // path no longer stats to it (replaced or deleted since).
            let proc_exe = proc_root.join(e.pid.to_string()).join("exe");
            if (self.stat)(&proc_exe) == Some((identity.dev, identity.ino)) {
                return path.clone();
            }
        }
        if let Some(indexed) = self.lookup(identity, Instant::now()) {
            return indexed;
        }
        match link {
            Some(path) => match (self.stat)(Path::new(&path)) {
                Some((dev, ino)) if dev == identity.dev && ino != identity.ino => String::new(),
                _ => path,
            },
            None => String::new(),
        }
    }
}

/// `(st_dev, st_ino)` of what `path` points to (`stat`, following links).
#[cfg(unix)]
fn stat_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some((m.dev(), m.ino()))
}

/// No `st_dev`/`st_ino` off unix: nothing verifies, so nothing is learned.
#[cfg(not(unix))]
fn stat_identity(_path: &Path) -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_ebpf::FsKind;

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    type Fs = Arc<Mutex<HashMap<String, (u64, u64)>>>;

    fn id(dev: u64, ino: u64) -> ExeIdentity {
        ExeIdentity { dev, ino }
    }

    /// An index whose `stat` reads a fake path → identity table.
    fn index(capacity: usize) -> (ExeIndex, Fs) {
        let fs: Fs = Arc::new(Mutex::new(HashMap::new()));
        let table = fs.clone();
        let ix = ExeIndex::new(vec![], capacity, Duration::from_secs(60))
            .with_stat(move |p| table.lock().unwrap().get(p.to_str()?).copied());
        (ix, fs)
    }

    fn put(fs: &Fs, path: &str, identity: (u64, u64)) {
        fs.lock().unwrap().insert(path.to_string(), identity);
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
        let (mut ix, fs) = index(10);
        put(&fs, "/usr/bin/bash", (1, 2));
        put(&fs, "/bin/bash", (1, 2));
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
        let (mut ix, fs) = index(2);
        for (p, i) in [("/a", 1), ("/b", 2), ("/c", 3)] {
            put(&fs, p, (1, i));
            ix.insert(id(1, i), p.into());
        }
        assert_eq!(ix.len(), 2);
        assert_eq!(ix.lookup(id(1, 3), Instant::now()), None);
        assert_eq!(ix.lookup(id(1, 1), Instant::now()).as_deref(), Some("/a"));
    }

    #[test]
    fn unknown_identity_or_none_gives_empty_exe_path() {
        let root = tempfile::tempdir().unwrap();
        let (mut ix, _fs) = index(10);
        assert_eq!(ix.exe_path(&event(None), root.path()), "");
        assert_eq!(ix.exe_path(&event(Some(id(5, 5))), root.path()), "");
    }

    #[test]
    fn an_indexed_identity_resolves_when_proc_is_gone() {
        let root = tempfile::tempdir().unwrap();
        let (mut ix, fs) = index(10);
        put(&fs, "/usr/bin/bash", (5, 5));
        ix.insert(id(5, 5), "/usr/bin/bash".into());
        assert_eq!(
            ix.exe_path(&event(Some(id(5, 5))), root.path()),
            "/usr/bin/bash"
        );
    }

    /// An inode reused after an upgrade: the stored path now stats to a
    /// different identity, so the hit is evicted instead of mislabelling.
    #[test]
    fn a_stale_entry_is_evicted_on_lookup() {
        let (mut ix, fs) = index(10);
        put(&fs, "/usr/bin/foo", (1, 7));
        ix.insert(id(1, 7), "/usr/bin/foo".into());
        // foo was replaced; inode 7 now belongs to something else.
        put(&fs, "/usr/bin/foo", (1, 99));
        assert_eq!(ix.lookup(id(1, 7), Instant::now()), None);
        assert_eq!(ix.len(), 0, "evicted");
    }

    #[test]
    fn a_stale_entry_is_corrected_by_a_rescan_insert() {
        let (mut ix, fs) = index(10);
        put(&fs, "/usr/bin/foo", (1, 7));
        ix.insert(id(1, 7), "/usr/bin/foo".into());
        put(&fs, "/usr/bin/foo", (1, 99));
        put(&fs, "/usr/bin/bash", (1, 7));
        // A scan finds the real owner of (1, 7): it overwrites the stale one.
        ix.insert(id(1, 7), "/usr/bin/bash".into());
        assert_eq!(
            ix.lookup(id(1, 7), Instant::now()).as_deref(),
            Some("/usr/bin/bash")
        );
    }

    #[test]
    fn learning_requires_the_path_to_stat_to_the_identity() {
        let (mut ix, fs) = index(10);
        // A decoy keeping comm "bash": /tmp/bash is a different file.
        put(&fs, "/tmp/bash", (1, 666));
        assert!(!ix.learn(id(1, 7), "/tmp/bash"));
        assert!(!ix.learn(id(1, 7), "/gone"));
        assert!(ix.is_empty());
        put(&fs, "/usr/bin/bash", (1, 7));
        assert!(ix.learn(id(1, 7), "/usr/bin/bash"));
        assert_eq!(
            ix.lookup(id(1, 7), Instant::now()).as_deref(),
            Some("/usr/bin/bash")
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

        let mut ix = ExeIndex::empty();
        ix.insert(identity, "/stale/other".into());
        // Link matches the identity: the link wins over the index...
        let got = ix.exe_path(&event(Some(identity)), root.path());
        assert_eq!(got, target.to_string_lossy());
        // ...and an unseen identity is learned from the hit.
        let mut fresh = ExeIndex::empty();
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

    /// A decoy that keeps comm "bash" passes `resolve_exe`'s comm rule but
    /// does not stat to the record's identity: it is returned for that
    /// record, never learned.
    #[cfg(unix)]
    #[test]
    fn a_comm_matched_decoy_is_not_learned() {
        let root = tempfile::tempdir().unwrap();
        let decoy = root.path().join("bash");
        std::fs::write(&decoy, b"x").unwrap();
        let pid_dir = root.path().join("4242");
        std::fs::create_dir(&pid_dir).unwrap();
        std::os::unix::fs::symlink(&decoy, pid_dir.join("exe")).unwrap();
        std::fs::write(
            pid_dir.join("comm"),
            b"bash
",
        )
        .unwrap();

        let real_bash = id(1, 7);
        let mut ix = ExeIndex::empty();
        let got = ix.exe_path(&event(Some(real_bash)), root.path());
        assert_eq!(got, decoy.to_string_lossy());
        assert!(ix.is_empty(), "unverified mapping must not be learned");
    }

    /// `/proc/4242/exe` → `<root>/later-bash` with comm "bash", as after
    /// `/tmp/bash` (the record's exe) exec'd `/usr/bin/bash`.
    #[cfg(unix)]
    fn exec_since_record(root: &Path) -> String {
        let later = root.join("later-bash");
        std::fs::write(&later, b"x").unwrap();
        let pid_dir = root.join("4242");
        std::fs::create_dir(&pid_dir).unwrap();
        std::os::unix::fs::symlink(&later, pid_dir.join("exe")).unwrap();
        std::fs::write(pid_dir.join("comm"), b"bash\n").unwrap();
        later.to_string_lossy().into_owned()
    }

    /// A comm-tied link whose path is a different inode on the record
    /// identity's own device is certainly another image: not reported.
    #[cfg(unix)]
    #[test]
    fn a_comm_tied_link_to_another_inode_on_the_same_device_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let later = exec_since_record(root.path());
        let (mut ix, fs) = index(10);
        put(&fs, &later, (1, 99)); // /usr/bin/bash
        let tmp_bash = id(1, 7); // the record's exe
        assert_eq!(ix.exe_path(&event(Some(tmp_bash)), root.path()), "");
        assert!(ix.is_empty());
    }

    /// The same case with the record's identity indexed: the indexed path
    /// wins over the comm-tied link.
    #[cfg(unix)]
    #[test]
    fn an_indexed_identity_wins_over_a_comm_tied_link() {
        let root = tempfile::tempdir().unwrap();
        let later = exec_since_record(root.path());
        let (mut ix, fs) = index(10);
        put(&fs, &later, (1, 99));
        put(&fs, "/opt/tools/bash", (1, 7));
        ix.insert(id(1, 7), "/opt/tools/bash".into());
        assert_eq!(
            ix.exe_path(&event(Some(id(1, 7))), root.path()),
            "/opt/tools/bash"
        );
    }

    /// The proc link itself stats to the record's identity although its
    /// path now names another file (replaced since): still the link.
    #[cfg(unix)]
    #[test]
    fn a_link_tied_by_the_proc_entry_is_kept_when_its_path_was_replaced() {
        let root = tempfile::tempdir().unwrap();
        let later = exec_since_record(root.path());
        let proc_exe = root.path().join("4242").join("exe");
        let (mut ix, fs) = index(10);
        put(&fs, &later, (1, 99));
        put(&fs, &proc_exe.to_string_lossy(), (1, 7));
        assert_eq!(ix.exe_path(&event(Some(id(1, 7))), root.path()), later);
        assert!(ix.is_empty(), "the replaced path must not be learned");
    }
}
