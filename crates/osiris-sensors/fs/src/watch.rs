//! Watch-path resolution for the eBPF fs backend.

use std::path::PathBuf;

use osiris_ebpf::dev_from_user;

/// Watched when `fs_watch_paths` is empty (Global Constraint #13), in order.
pub const DEFAULT_WATCH_PATHS: &[&str] = &[
    "/etc",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/lib/systemd",
    "/var/spool/cron",
    "/var/www",
    "/root",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
];

/// `statfs.f_type` of btrfs and overlayfs: their `st_dev` is not the
/// superblock device the kernel reports, so only the inode can match.
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E;
const OVERLAYFS_SUPER_MAGIC: i64 = 0x794C_7630;

/// A `WATCH` map key. `dev` is a kernel `dev_t` (`MAJOR << 20 | MINOR`);
/// 0 means "match the inode alone".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchKey {
    pub dev: u32,
    pub ino: u64,
}

/// What a list of configured watch paths resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchResolution {
    pub keys: Vec<WatchKey>,
    /// At least one key has `dev == 0` (`WATCH_FLAGS` bit 0).
    pub inode_only: bool,
    /// One message per path that could not be watched, naming the path.
    pub skipped: Vec<String>,
}

/// The `WATCH` key of a directory with user-space `st_dev`/`ino` on a
/// filesystem of type `fs_magic` (`statfs.f_type`): the kernel `dev_t`
/// derived with [`dev_from_user`], except on btrfs and overlayfs, which
/// match by inode only (`dev` 0). Pure (Global Constraint #14).
pub fn watch_key(st_dev: u64, ino: u64, fs_magic: i64) -> WatchKey {
    // f_type is a signed word on some targets; compare its 32 low bits.
    match fs_magic & 0xffff_ffff {
        BTRFS_SUPER_MAGIC | OVERLAYFS_SUPER_MAGIC => WatchKey { dev: 0, ino },
        _ => WatchKey {
            dev: dev_from_user(st_dev),
            ino,
        },
    }
}

/// Resolve each configured path (symlinks followed) to a watch key. A path
/// that is missing, not a directory or not stat-able is skipped and named
/// in `skipped`; identical keys are kept once. Off Linux every path is
/// skipped.
pub fn resolve_watch_paths(paths: &[PathBuf]) -> WatchResolution {
    let mut keys: Vec<WatchKey> = Vec::new();
    let mut skipped = Vec::new();
    for path in paths {
        match resolve_one(path) {
            Ok(key) => {
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
            Err(why) => skipped.push(format!("{}: {why}", path.display())),
        }
    }
    let inode_only = keys.iter().any(|k| k.dev == 0);
    WatchResolution {
        keys,
        inode_only,
        skipped,
    }
}

#[cfg(target_os = "linux")]
fn resolve_one(path: &std::path::Path) -> Result<WatchKey, String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "not found".to_string(),
        _ => format!("cannot stat: {e}"),
    })?;
    if !meta.is_dir() {
        return Err("not a directory".to_string());
    }
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "path contains a NUL byte".to_string())?;
    let mut st = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `c_path` is a valid NUL-terminated string and `st` is a
    // writable `statfs` buffer; `st` is read only after statfs returned 0.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), st.as_mut_ptr()) };
    if rc != 0 {
        return Err(format!(
            "cannot statfs: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: statfs returned 0, so it initialised the whole struct.
    let st = unsafe { st.assume_init() };
    #[allow(clippy::unnecessary_cast)] // f_type's width differs per target
    let magic = st.f_type as i64;
    Ok(watch_key(meta.dev(), meta.ino(), magic))
}

#[cfg(not(target_os = "linux"))]
fn resolve_one(_path: &std::path::Path) -> Result<WatchKey, String> {
    Err("watch paths need Linux".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXT4: i64 = 0xEF53;
    const BTRFS: i64 = 0x9123_683E;
    const OVERLAYFS: i64 = 0x794C_7630;

    #[test]
    fn watch_key_rules() {
        // glibc makedev(8, 1)
        let st_dev = (8u64 << 8) | 1;
        assert_eq!(
            watch_key(st_dev, 99, EXT4),
            WatchKey {
                dev: (8 << 20) | 1,
                ino: 99
            }
        );
        assert_eq!(watch_key(st_dev, 99, BTRFS), WatchKey { dev: 0, ino: 99 });
        assert_eq!(
            watch_key(st_dev, 99, OVERLAYFS),
            WatchKey { dev: 0, ino: 99 }
        );
    }

    #[test]
    fn default_watch_paths_follow_gc_13() {
        assert_eq!(
            DEFAULT_WATCH_PATHS.join(" "),
            "/etc /usr/bin /usr/sbin /usr/local/bin /usr/lib/systemd /var/spool/cron /var/www /root /tmp /var/tmp /dev/shm"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn off_linux_every_path_is_skipped() {
        let r = resolve_watch_paths(&[PathBuf::from("/etc"), PathBuf::from("/tmp")]);
        assert!(r.keys.is_empty() && !r.inode_only);
        assert_eq!(r.skipped.len(), 2);
        assert!(r
            .skipped
            .iter()
            .all(|s| s.contains("watch paths need Linux")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn watch_resolution_skips_bad_paths() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let file = dir.path().join("plain.txt");
        std::fs::write(&file, b"x").unwrap();
        let good = dir.path().join("good");
        std::fs::create_dir(&good).unwrap();

        let r = resolve_watch_paths(&[missing.clone(), file.clone(), good]);
        assert_eq!(r.keys.len(), 1, "{r:?}");
        assert_eq!(r.skipped.len(), 2, "{r:?}");
        assert!(
            r.skipped[0].contains(&missing.display().to_string()),
            "{r:?}"
        );
        assert!(r.skipped[1].contains(&file.display().to_string()), "{r:?}");
    }
}
