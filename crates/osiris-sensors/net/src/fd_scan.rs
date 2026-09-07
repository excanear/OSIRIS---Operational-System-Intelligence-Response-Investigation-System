use std::collections::HashMap;
use std::path::Path;

/// Extracts the inode from a `/proc/<pid>/fd/<n>` symlink target of the
/// form `socket:[12345]`. Every other target shape is `None`.
pub fn extract_socket_inode(link_target: &str) -> Option<u64> {
    let inner = link_target.strip_prefix("socket:[")?;
    let inner = inner.strip_suffix(']')?;
    inner.parse().ok()
}

/// Walks every numeric (pid) directory under `proc_root` and builds an
/// `inode -> pid` map from every socket-typed fd found under each one's
/// `fd` subdirectory. A missing `proc_root`, a pid directory with no
/// readable `fd` subdirectory, or an unreadable individual link is skipped,
/// never panicked on.
pub fn scan_socket_inodes(proc_root: &Path) -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return map;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd_entry in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd_entry.path()) else {
                continue;
            };
            if let Some(inode) = extract_socket_inode(&target.to_string_lossy()) {
                map.insert(inode, pid);
            }
        }
    }
    map
}

/// Best-effort `exe_path`/`comm` lookup for an already-attributed pid.
/// Returns empty strings for whichever half could not be read (the process
/// may have exited between the fd-scan and this read) — never an error,
/// matching `scan_socket_inodes`'s "process churn is normal" discipline.
pub fn read_process_identity(proc_root: &Path, pid: u32) -> (String, String) {
    let exe_path = std::fs::read_link(proc_root.join(pid.to_string()).join("exe"))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let comm = std::fs::read_to_string(proc_root.join(pid.to_string()).join("comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    (exe_path, comm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_inode_from_a_well_formed_socket_link_target() {
        assert_eq!(extract_socket_inode("socket:[12345]"), Some(12345));
    }

    #[test]
    fn rejects_a_non_socket_link_target() {
        assert_eq!(extract_socket_inode("/dev/null"), None);
        assert_eq!(extract_socket_inode("pipe:[999]"), None);
    }

    #[test]
    fn rejects_a_malformed_socket_link_target() {
        assert_eq!(extract_socket_inode("socket:[not-a-number]"), None);
        assert_eq!(extract_socket_inode("socket:[12345"), None);
    }

    #[test]
    fn scanning_a_proc_root_with_no_pid_directories_yields_an_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        let map = scan_socket_inodes(dir.path());
        assert!(map.is_empty());
    }

    #[test]
    fn scanning_a_missing_proc_root_yields_an_empty_map_not_a_panic() {
        let map = scan_socket_inodes(std::path::Path::new("/definitely/does/not/exist"));
        assert!(map.is_empty());
    }

    #[test]
    fn a_pid_directory_with_no_fd_subdirectory_is_skipped_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("300")).unwrap();
        let map = scan_socket_inodes(dir.path());
        assert!(map.is_empty());
    }

    /// Integration proof of the real directory walk: creates actual
    /// symlinks inside a tempdir and scans it. Windows symlink creation
    /// needs Developer Mode or admin rights, neither guaranteed on this dev
    /// machine (Phase 3 plan Global Constraints #11) — on a permission
    /// error this test prints why and returns early rather than failing the
    /// suite. The pure parsing logic above is exercised unconditionally
    /// regardless of this test's outcome.
    #[test]
    fn scans_real_symlinks_into_an_inode_to_pid_map() {
        let dir = tempfile::tempdir().unwrap();
        let fd_dir = dir.path().join("300").join("fd");
        std::fs::create_dir_all(&fd_dir).unwrap();
        let link_path = fd_dir.join("3");

        if let Err(e) = make_symlink("socket:[12345]", &link_path) {
            eprintln!(
                "skipping scans_real_symlinks_into_an_inode_to_pid_map: cannot create a symlink on this platform/process ({e}); the pure extract_socket_inode parsing is still covered by other tests"
            );
            return;
        }

        let map = scan_socket_inodes(dir.path());
        assert_eq!(map.get(&12345), Some(&300));
    }

    #[cfg(unix)]
    fn make_symlink(target: &str, link: &std::path::Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn make_symlink(target: &str, link: &std::path::Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }

    #[test]
    fn read_process_identity_returns_empty_strings_when_nothing_is_readable() {
        let dir = tempfile::tempdir().unwrap();
        let (exe, comm) = read_process_identity(dir.path(), 999);
        assert_eq!(exe, "");
        assert_eq!(comm, "");
    }
}
