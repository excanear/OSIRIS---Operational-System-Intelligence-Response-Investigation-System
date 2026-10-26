//! Kernel exe identity and the shared `exe_path` resolver.
//!
//! BPF records taken in process context carry the identity of the task's
//! executable as the kernel saw it (`mm->exe_file->f_inode`: the inode
//! number and the superblock's `s_dev`). User space only sees
//! `/proc/<pid>/exe` some time later, when the pid may have exec'd again or
//! been reused, so the link is trusted only when it can be tied back to the
//! record. [`resolve_exe`] implements steps 1 and 2 of that chain; the
//! caller supplies step 3 (the exec filename, or `""` for network records).

use std::path::Path;

/// The executable's `(st_dev, st_ino)` as reported by the kernel, with
/// `dev` already in the user-space `st_dev` encoding (see [`dev_to_user`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExeIdentity {
    pub dev: u64,
    pub ino: u64,
}

/// Kernel-internal `dev_t` (`MAJOR = dev >> 20`, `MINOR = dev & 0xfffff`)
/// → the user-space `st_dev` encoding glibc's `makedev` produces (what
/// `stat(2)` reports): major bits 0–11 at 8–19 and 32–43 for the rest,
/// minor bits 0–7 at 0–7 and the rest from bit 20.
pub fn dev_to_user(kernel_dev: u32) -> u64 {
    let major = u64::from(kernel_dev >> 20);
    let minor = u64::from(kernel_dev & 0xf_ffff);
    ((major & 0xffff_f000) << 32)
        | ((major & 0xfff) << 8)
        | ((minor & 0xffff_ff00) << 12)
        | (minor & 0xff)
}

/// Inverse of [`dev_to_user`]: a user-space `st_dev` (glibc `makedev`
/// encoding) → the kernel-internal `dev_t` (`MAJOR << 20 | MINOR`).
pub fn dev_from_user(st_dev: u64) -> u32 {
    let major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & 0xffff_f000);
    let minor = (st_dev & 0xff) | ((st_dev >> 12) & 0xffff_ff00);
    // Kernel dev_t has 12 major bits and 20 minor bits; truncate the rest.
    (((major & 0xfff) << 20) | (minor & 0xf_ffff)) as u32
}

/// `exe_path` for a record of `pid` taken from `<proc_root>/<pid>/exe`,
/// or `None` when the link cannot be tied to the record (the caller then
/// falls back to the exec filename, or `""` for network records):
///
/// 1. the link target, if `stat(<proc_root>/<pid>/exe)` has the kernel
///    identity `exe` (unix only; elsewhere this step is skipped);
/// 2. else the link target, if `<proc_root>/<pid>/comm` read *after* the
///    link equals `record_comm` (the 11b-1 rule, see [`comm_checked_link`]).
///    This covers no identity, a failed `stat` and a mismatch — btrfs
///    subvolumes and overlayfs report a different `(st_dev, st_ino)` than
///    the kernel's inode — so the identity check never makes the result
///    worse than 11b-1's.
///
/// Order matters: the link is read before the `stat` and the comm read,
/// so an exec between the reads changes what those see and rejects the
/// (now stale) link instead of trusting it.
pub fn resolve_exe(
    proc_root: &Path,
    pid: u32,
    exe: Option<ExeIdentity>,
    record_comm: &str,
) -> Option<String> {
    let dir = proc_root.join(pid.to_string());
    let link = std::fs::read_link(dir.join("exe"))
        .ok()?
        .to_string_lossy()
        .into_owned();
    if exe.is_some() && stat_identity(&dir.join("exe")) == exe {
        return Some(link);
    }
    let comm = proc_comm(proc_root, pid);
    comm_checked_link(Some(link), comm.as_deref(), record_comm)
}

/// `(st_dev, st_ino)` of what `path` points to (`stat`, following links).
#[cfg(unix)]
fn stat_identity(path: &Path) -> Option<ExeIdentity> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some(ExeIdentity {
        dev: m.dev(),
        ino: m.ino(),
    })
}

/// No `st_dev`/`st_ino` off unix: step 1 never matches.
#[cfg(not(unix))]
fn stat_identity(_path: &Path) -> Option<ExeIdentity> {
    None
}

/// `<proc_root>/<pid>/comm` without its trailing newline, when readable.
fn proc_comm(proc_root: &Path, pid: u32) -> Option<Vec<u8>> {
    let mut comm = std::fs::read(proc_root.join(pid.to_string()).join("comm")).ok()?;
    if comm.last() == Some(&b'\n') {
        comm.pop();
    }
    Some(comm)
}

/// The kernel keeps at most `TASK_COMM_LEN - 1` = 15 bytes of a comm.
const COMM_MAX_BYTES: usize = 15;

/// Whether `/proc/<pid>/comm`'s bytes name the same task comm as the
/// record's (decoded like the record: at most 15 bytes, lossy UTF-8).
fn same_comm(proc_comm: &[u8], record_comm: &str) -> bool {
    let proc_comm = &proc_comm[..proc_comm.len().min(COMM_MAX_BYTES)];
    String::from_utf8_lossy(proc_comm) == record_comm
}

/// The 11b-1 rule: the `/proc/<pid>/exe` link is trusted only if
/// `/proc/<pid>/comm`, read *after* the link, still equals the comm the
/// kernel captured in the record. A mismatch means the pid has exec'd
/// again (`sh -c 'cmd'`, `system()`, wrappers) or was reused since the
/// record was written, so the link names a later image. A process that
/// renamed itself (`PR_SET_NAME`) only loses the link, it is never
/// mislabeled.
fn comm_checked_link(
    link: Option<String>,
    proc_comm: Option<&[u8]>,
    record_comm: &str,
) -> Option<String> {
    match (link, proc_comm) {
        (Some(link), Some(comm)) if same_comm(comm, record_comm) => Some(link),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_to_user_encodes_like_glibc() {
        assert_eq!(dev_to_user((8 << 20) | 1), 2049);
        assert_eq!(dev_to_user((259 << 20) | 0x12345), 0x1231_0345);
        assert_eq!(dev_to_user(0), 0);
    }

    #[test]
    fn dev_from_user_round_trips() {
        for (major, minor) in [(8u32, 1u32), (259, 3), (0, 47), (4095, 1_048_575)] {
            let k = (major << 20) | minor;
            assert_eq!(dev_from_user(dev_to_user(k)), k, "({major},{minor})");
        }
    }

    #[test]
    fn exe_link_is_accepted_only_with_a_matching_comm() {
        let link = || Some("/usr/bin/dash".to_string());
        let dash = Some("/usr/bin/dash".to_string());
        // Match (trailing newline already stripped by proc_comm).
        assert_eq!(comm_checked_link(link(), Some(b"sh"), "sh"), dash);
        // A later exec or a reused pid: different comm.
        assert_eq!(comm_checked_link(link(), Some(b"curl"), "sh"), None);
        // comm unreadable (the process exited between the two reads).
        assert_eq!(comm_checked_link(link(), None, "sh"), None);
        // Link unreadable.
        assert_eq!(comm_checked_link(None, Some(b"sh"), "sh"), None);
        // comm is truncated to 15 bytes on both sides.
        assert_eq!(
            comm_checked_link(link(), Some(b"a-very-long-name"), "a-very-long-nam"),
            dash
        );
        // Non-UTF-8 comm bytes compare like the record decodes them.
        assert_eq!(
            comm_checked_link(link(), Some(b"x\xffy"), "x\u{FFFD}y"),
            dash
        );
        // A prefix is not a match.
        assert_eq!(comm_checked_link(link(), Some(b"s"), "sh"), None);
    }

    #[test]
    fn proc_comm_drops_only_the_trailing_newline() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("77")).unwrap();
        std::fs::write(root.path().join("77").join("comm"), b"sh\n").unwrap();
        assert_eq!(proc_comm(root.path(), 77).as_deref(), Some(&b"sh"[..]));
        assert_eq!(proc_comm(root.path(), 78), None);
    }

    #[cfg(unix)]
    fn symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }

    /// A fake `<root>/77/` with `exe` → `<root>/dash` and the given `comm`
    /// file contents; `None` (test skipped) when symlinks are unavailable.
    fn fake_proc(comm: &[u8]) -> Option<(tempfile::TempDir, std::path::PathBuf)> {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("dash");
        std::fs::write(&target, b"").unwrap();
        std::fs::create_dir(root.path().join("77")).unwrap();
        std::fs::write(root.path().join("77").join("comm"), comm).unwrap();
        if let Err(e) = symlink(&target, &root.path().join("77").join("exe")) {
            eprintln!("SKIPPED: cannot create a symlink on this host ({e})");
            return None;
        }
        Some((root, target))
    }

    /// The identity a kernel record would carry for `path`.
    #[cfg(unix)]
    fn identity_of(path: &Path) -> ExeIdentity {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(path).unwrap();
        ExeIdentity {
            dev: m.dev(),
            ino: m.ino(),
        }
    }

    #[test]
    fn resolve_exe_fallback_chain() {
        // Missing link: nothing to resolve, whatever the identity and comm
        // say. Runs everywhere (no symlink needed).
        let empty = tempfile::tempdir().unwrap();
        std::fs::create_dir(empty.path().join("77")).unwrap();
        std::fs::write(empty.path().join("77").join("comm"), b"curl\n").unwrap();
        assert_eq!(resolve_exe(empty.path(), 77, None, "curl"), None);
        assert_eq!(
            resolve_exe(
                empty.path(),
                77,
                Some(ExeIdentity { dev: 1, ino: 1 }),
                "curl"
            ),
            None
        );

        let Some((root, target)) = fake_proc(b"curl\n") else {
            return;
        };
        let link = Some(target.to_string_lossy().into_owned());
        let other = Some(ExeIdentity { dev: 1, ino: 1 });

        // Step 1: the identity matches, so the link wins even though comm
        // says the task renamed itself. Off unix step 1 is skipped and the
        // comm mismatch rejects the link.
        #[cfg(unix)]
        assert_eq!(
            resolve_exe(root.path(), 77, Some(identity_of(&target)), "sh"),
            link
        );
        #[cfg(not(unix))]
        assert_eq!(
            resolve_exe(root.path(), 77, Some(ExeIdentity { dev: 0, ino: 0 }), "sh"),
            None
        );

        // Step 2: identity mismatch (btrfs/overlayfs) or no identity, but
        // comm still matches.
        assert_eq!(resolve_exe(root.path(), 77, other, "curl"), link);
        assert_eq!(resolve_exe(root.path(), 77, None, "curl"), link);

        // Neither the identity nor comm matches: a later image.
        assert_eq!(resolve_exe(root.path(), 77, other, "sh"), None);
        assert_eq!(resolve_exe(root.path(), 77, None, "sh"), None);

        // No such pid: no link to resolve.
        assert_eq!(resolve_exe(root.path(), 78, None, "curl"), None);
        #[cfg(unix)]
        assert_eq!(
            resolve_exe(root.path(), 78, Some(identity_of(&target)), "curl"),
            None
        );
    }
}
