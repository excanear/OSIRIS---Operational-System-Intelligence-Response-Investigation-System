//! Executors for signed commands. The pure parsing helpers are portable (and
//! unit-tested everywhere); the `/proc`- and syscall-touching `LinuxExecutor`
//! exists only on Linux, with `UnsupportedExecutor` elsewhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use osiris_command::{ActionExecutor, ExecDetail, ExecFailure, FailCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ---------------------------------------------------------------- pure helpers

/// The fields of `/proc/<pid>/stat` the executor needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatInfo {
    pub state: char,
    pub ppid: u32,
    /// Field 22: start time in clock ticks after boot.
    pub starttime_ticks: u64,
}

/// Parses `/proc/<pid>/stat`. `comm` (field 2) may contain spaces and
/// parentheses, so everything is located relative to the LAST `)`.
pub fn parse_stat(s: &str) -> Option<StatInfo> {
    let rest = &s[s.rfind(')')? + 1..];
    let mut it = rest.split_whitespace();
    // rest starts at field 3 (state); field 4 is ppid; field 22 is index 19.
    let state = it.next()?.chars().next()?;
    let ppid = it.next()?.parse().ok()?;
    let starttime_ticks = it.nth(17)?.parse().ok()?;
    Some(StatInfo {
        state,
        ppid,
        starttime_ticks,
    })
}

/// Boot time (seconds since the epoch) from `/proc/stat`.
pub fn parse_btime(proc_stat: &str) -> Option<u64> {
    proc_stat
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()
}

/// Process start time in nanoseconds since the Unix epoch.
pub fn start_ns(btime_s: u64, starttime_ticks: u64, clk_tck: u64) -> Option<u64> {
    if clk_tck == 0 {
        return None;
    }
    let boot = btime_s.checked_mul(1_000_000_000)?;
    let since_boot = (starttime_ticks as u128 * 1_000_000_000 / clk_tck as u128) as u64;
    boot.checked_add(since_boot)
}

/// OSIRIS device encoding `(major << 32) | minor`.
pub fn encode_dev(major: u64, minor: u64) -> u64 {
    (major << 32) | (minor & 0xffff_ffff)
}

/// Splits a Linux `st_dev` (glibc `gnu_dev_major/minor`) and re-encodes it.
pub fn encode_st_dev(st_dev: u64) -> u64 {
    let major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & !0xfff);
    let minor = (st_dev & 0xff) | ((st_dev >> 12) & !0xff);
    encode_dev(major, minor)
}

/// Walks the parent chain of `pid` (excluding `pid`), stopping at 0, on a
/// lookup failure, on a cycle or after 64 hops.
pub fn ancestors_from(pid: u32, ppid_of: impl Fn(u32) -> Option<u32>) -> Vec<u32> {
    let mut out = Vec::new();
    let mut cur = pid;
    for _ in 0..64 {
        match ppid_of(cur) {
            Some(p) if p != 0 && !out.contains(&p) && p != pid => {
                out.push(p);
                cur = p;
            }
            _ => break,
        }
    }
    out
}

/// The Agent's ancestors, from `/proc` (empty where `/proc` is unavailable).
pub fn ancestors_of(pid: u32) -> Vec<u32> {
    ancestors_from(pid, |p| {
        let s = std::fs::read_to_string(format!("/proc/{p}/stat")).ok()?;
        Some(parse_stat(&s)?.ppid)
    })
}

/// Lowercase hex SHA-256 of a stream.
pub fn sha256_reader(mut r: impl Read) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Stored next to every vaulted file as `<uuid>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sidecar {
    pub path: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub sha256: String,
    /// Milliseconds since the Unix epoch.
    pub quarantined_at: u64,
}

/// `(vaulted file, sidecar)` for a quarantine id.
pub fn vault_paths(vault: &Path, id: Uuid) -> (PathBuf, PathBuf) {
    (vault.join(id.to_string()), vault.join(format!("{id}.json")))
}

fn fail(code: FailCode, message: impl Into<String>) -> ExecFailure {
    ExecFailure {
        code,
        message: message.into(),
    }
}

// ------------------------------------------------------------- non-Linux stub

/// Commands cannot be executed on this platform.
pub struct UnsupportedExecutor;

impl ActionExecutor for UnsupportedExecutor {
    fn terminate(&self, _: u32, _: &str, _: u64, _: bool) -> Result<ExecDetail, ExecFailure> {
        Err(fail(FailCode::Unsupported, "unsupported platform"))
    }
    fn quarantine(&self, _: &str, _: u64, _: u64, _: bool) -> Result<ExecDetail, ExecFailure> {
        Err(fail(FailCode::Unsupported, "unsupported platform"))
    }
    fn restore(&self, _: Uuid, _: bool) -> Result<ExecDetail, ExecFailure> {
        Err(fail(FailCode::Unsupported, "unsupported platform"))
    }
}

#[cfg(target_os = "linux")]
pub fn default_executor(vault: PathBuf) -> Arc<dyn ActionExecutor> {
    Arc::new(LinuxExecutor { vault })
}

#[cfg(not(target_os = "linux"))]
pub fn default_executor(_vault: PathBuf) -> Arc<dyn ActionExecutor> {
    Arc::new(UnsupportedExecutor)
}

// ------------------------------------------------------------------- Linux

#[cfg(target_os = "linux")]
pub use linux::LinuxExecutor;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use osiris_command::process_started_by;
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    pub struct LinuxExecutor {
        pub vault: PathBuf,
    }

    struct Ident {
        exe: PathBuf,
        start_ns: u64,
        starttime_ticks: u64,
    }

    fn clk_tck() -> u64 {
        // SAFETY: sysconf has no preconditions.
        let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if v > 0 {
            v as u64
        } else {
            100
        }
    }

    fn read_stat(pid: u32) -> std::io::Result<StatInfo> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        parse_stat(&s).ok_or_else(|| std::io::Error::other("unparseable stat"))
    }

    fn read_identity(pid: u32) -> Result<Ident, ExecFailure> {
        let proc_dir = format!("/proc/{pid}");
        if !Path::new(&proc_dir).exists() {
            return Err(fail(FailCode::NotFound, format!("no process {pid}")));
        }
        let unverifiable = |what: &str| fail(FailCode::Unverifiable, format!("pid {pid}: {what}"));
        let stat = read_stat(pid).map_err(|_| unverifiable("stat unreadable"))?;
        let exe = std::fs::read_link(format!("{proc_dir}/exe"))
            .map_err(|_| unverifiable("exe unreadable (kernel thread or no access)"))?;
        if exe.as_os_str().is_empty() {
            return Err(unverifiable("empty exe"));
        }
        if pid == 2 || stat.ppid == 2 {
            return Err(unverifiable("kernel thread"));
        }
        let btime = std::fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|s| parse_btime(&s))
            .ok_or_else(|| unverifiable("boot time unreadable"))?;
        let start = start_ns(btime, stat.starttime_ticks, clk_tck())
            .ok_or_else(|| unverifiable("start time not computable"))?;
        Ok(Ident {
            exe,
            start_ns: start,
            starttime_ticks: stat.starttime_ticks,
        })
    }

    fn verify_identity(pid: u32, exe_path: &str, observed: u64) -> Result<Ident, ExecFailure> {
        let id = read_identity(pid)?;
        if id.exe != Path::new(exe_path) {
            return Err(fail(
                FailCode::TargetChanged,
                format!("pid {pid} runs {} not {exe_path}", id.exe.display()),
            ));
        }
        if !process_started_by(id.start_ns, observed) {
            return Err(fail(
                FailCode::TargetChanged,
                format!("pid {pid} started after the observation"),
            ));
        }
        Ok(id)
    }

    /// True once the process is gone, a zombie, or the pid was reused.
    fn exited(pid: u32, ticks: u64) -> bool {
        match read_stat(pid) {
            Ok(s) => s.state == 'Z' || s.state == 'X' || s.starttime_ticks != ticks,
            Err(_) => true,
        }
    }

    fn wait_exit(pid: u32, ticks: u64, max: Duration) -> bool {
        let deadline = Instant::now() + max;
        loop {
            if exited(pid, ticks) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn signal(pid: u32, sig: libc::c_int) -> Result<(), ExecFailure> {
        let p = i32::try_from(pid).map_err(|_| fail(FailCode::Unverifiable, "pid out of range"))?;
        // SAFETY: plain kill(2); pid is > 0 (checked by the caller).
        if unsafe { libc::kill(p, sig) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ESRCH) {
            Err(fail(FailCode::NotFound, "process vanished"))
        } else {
            Err(fail(FailCode::Io, format!("kill failed: {e}")))
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn io_fail(what: &str, e: std::io::Error) -> ExecFailure {
        fail(FailCode::Io, format!("{what}: {e}"))
    }

    fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
        a.ino() == b.ino() && a.dev() == b.dev()
    }

    impl LinuxExecutor {
        fn ensure_vault(&self) -> Result<(), ExecFailure> {
            crate::control::ensure_vault(&self.vault).map_err(|e| io_fail("vault", e))
        }

        fn hash_file(path: &Path) -> Result<String, ExecFailure> {
            let f = File::open(path).map_err(|e| io_fail("open for hashing", e))?;
            sha256_reader(f).map_err(|e| io_fail("hash", e))
        }
    }

    impl ActionExecutor for LinuxExecutor {
        fn terminate(
            &self,
            pid: u32,
            exe_path: &str,
            observed_at_ns: u64,
            dry_run: bool,
        ) -> Result<ExecDetail, ExecFailure> {
            if pid == 0 {
                return Err(fail(FailCode::Unverifiable, "pid 0"));
            }
            let id = verify_identity(pid, exe_path, observed_at_ns)?;
            if dry_run {
                return Ok(ExecDetail {
                    summary: format!("terminate pid {pid} ({exe_path})"),
                    quarantine_id: None,
                    sha256: None,
                    signal: None,
                });
            }
            signal(pid, libc::SIGTERM)?;
            if wait_exit(pid, id.starttime_ticks, Duration::from_secs(5)) {
                return Ok(ExecDetail {
                    summary: format!("terminated pid {pid}"),
                    quarantine_id: None,
                    sha256: None,
                    signal: Some("SIGTERM".into()),
                });
            }
            // Still alive: prove it is the same process before the hard kill.
            verify_identity(pid, exe_path, observed_at_ns)?;
            signal(pid, libc::SIGKILL)?;
            if wait_exit(pid, id.starttime_ticks, Duration::from_secs(5)) {
                Ok(ExecDetail {
                    summary: format!("killed pid {pid}"),
                    quarantine_id: None,
                    sha256: None,
                    signal: Some("SIGKILL".into()),
                })
            } else {
                Err(fail(FailCode::Io, format!("pid {pid} survived SIGKILL")))
            }
        }

        fn quarantine(
            &self,
            path: &str,
            inode: u64,
            device_id: u64,
            dry_run: bool,
        ) -> Result<ExecDetail, ExecFailure> {
            // Open the final component without following symlinks, then judge
            // the OPEN file, so a swap after the guard's lexical check cannot
            // redirect us (e.g. a dangling symlink into the vault).
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)
                .map_err(|e| match e.raw_os_error() {
                    Some(libc::ENOENT) => fail(FailCode::NotFound, format!("{path}: not found")),
                    Some(libc::ELOOP) => {
                        fail(FailCode::TargetChanged, format!("{path} is a symlink"))
                    }
                    _ => io_fail("open", e),
                })?;
            let meta = file.metadata().map_err(|e| io_fail("fstat", e))?;
            if !meta.is_file() {
                return Err(fail(FailCode::TargetChanged, "not a regular file"));
            }
            if meta.ino() != inode || encode_st_dev(meta.dev()) != device_id {
                return Err(fail(FailCode::TargetChanged, "inode/device changed"));
            }
            self.ensure_vault()?;
            let vault_meta = std::fs::metadata(&self.vault).map_err(|e| io_fail("vault", e))?;
            if same_file(&vault_meta, &meta) {
                return Err(fail(FailCode::TargetChanged, "protected: the vault itself"));
            }
            // Where does this open file really live? Refuse anything in the vault.
            let real = std::fs::read_link(format!("/proc/self/fd/{}", file_fd(&file)))
                .map_err(|_| fail(FailCode::Unverifiable, "cannot resolve open file"))?;
            let vault_real = std::fs::canonicalize(&self.vault).map_err(|e| io_fail("vault", e))?;
            if real.starts_with(&vault_real) {
                return Err(fail(FailCode::TargetChanged, "protected: inside the vault"));
            }
            if dry_run {
                return Ok(ExecDetail {
                    summary: format!("quarantine {path}"),
                    quarantine_id: None,
                    sha256: None,
                    signal: None,
                });
            }

            let id = Uuid::new_v4();
            let (vaulted, sidecar_path) = vault_paths(&self.vault, id);
            match std::fs::rename(path, &vaulted) {
                Ok(()) => {
                    // The path could have been swapped after the open: whatever
                    // we moved must be the file we checked, or we put it back.
                    let moved = std::fs::symlink_metadata(&vaulted)
                        .map_err(|e| io_fail("stat vault", e))?;
                    if !same_file(&moved, &meta) {
                        let _ = std::fs::rename(&vaulted, path);
                        return Err(fail(FailCode::TargetChanged, "file swapped during move"));
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
                    copy_across(&file, &meta, path, &vaulted)?;
                }
                Err(e) => return Err(io_fail("move into vault", e)),
            }
            let sha = Self::hash_file(&vaulted)?;
            std::fs::set_permissions(&vaulted, std::fs::Permissions::from_mode(0))
                .map_err(|e| io_fail("chmod 0000", e))?;
            let car = Sidecar {
                path: path.to_string(),
                mode: meta.mode() & 0o7777,
                uid: meta.uid(),
                gid: meta.gid(),
                sha256: sha.clone(),
                quarantined_at: now_ms(),
            };
            let json = serde_json::to_vec_pretty(&car)
                .map_err(|e| fail(FailCode::Io, format!("sidecar encode: {e}")))?;
            let written = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&sidecar_path)
                .and_then(|mut f| f.write_all(&json).and_then(|_| f.sync_all()));
            if let Err(e) = written {
                let _ = std::fs::remove_file(&sidecar_path);
                let _ =
                    std::fs::set_permissions(&vaulted, std::fs::Permissions::from_mode(car.mode));
                let _ = std::fs::rename(&vaulted, path);
                return Err(io_fail("write sidecar", e));
            }
            Ok(ExecDetail {
                summary: format!("quarantined {path}"),
                quarantine_id: Some(id),
                sha256: Some(sha),
                signal: None,
            })
        }

        fn restore(&self, id: Uuid, dry_run: bool) -> Result<ExecDetail, ExecFailure> {
            let (vaulted, sidecar_path) = vault_paths(&self.vault, id);
            let raw = std::fs::read(&sidecar_path).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => {
                    fail(FailCode::NotFound, format!("no quarantine {id}"))
                }
                _ => io_fail("read sidecar", e),
            })?;
            let car: Sidecar = serde_json::from_slice(&raw)
                .map_err(|e| fail(FailCode::Unverifiable, format!("bad sidecar: {e}")))?;
            let dest = PathBuf::from(&car.path);
            if !dest.is_absolute() || dest.starts_with(&self.vault) {
                return Err(fail(FailCode::Unverifiable, "sidecar path not restorable"));
            }
            // The vaulted file is mode 0000; make it readable to its owner.
            std::fs::set_permissions(&vaulted, std::fs::Permissions::from_mode(0o400)).map_err(
                |e| match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        fail(FailCode::NotFound, "vaulted file missing")
                    }
                    _ => io_fail("chmod vaulted file", e),
                },
            )?;
            let relock = |r: Result<ExecDetail, ExecFailure>| {
                if r.is_err() {
                    let _ = std::fs::set_permissions(&vaulted, std::fs::Permissions::from_mode(0));
                }
                r
            };
            relock((|| {
                if Self::hash_file(&vaulted)? != car.sha256 {
                    return Err(fail(FailCode::TargetChanged, "vaulted file hash mismatch"));
                }
                if std::fs::symlink_metadata(&dest).is_ok() {
                    return Err(fail(
                        FailCode::DestinationExists,
                        format!("{} exists", dest.display()),
                    ));
                }
                if dry_run {
                    return Ok(ExecDetail {
                        summary: format!("restore {}", dest.display()),
                        quarantine_id: Some(id),
                        sha256: Some(car.sha256.clone()),
                        signal: None,
                    });
                }
                // hard_link fails atomically if the destination appeared meanwhile.
                match std::fs::hard_link(&vaulted, &dest) {
                    Ok(()) => {}
                    Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
                        let src = File::open(&vaulted).map_err(|e| io_fail("open vaulted", e))?;
                        let mut out = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(&dest)
                            .map_err(dest_err)?;
                        std::io::copy(&mut &src, &mut out)
                            .and_then(|_| out.sync_all())
                            .map_err(|e| {
                                let _ = std::fs::remove_file(&dest);
                                io_fail("copy back", e)
                            })?;
                    }
                    Err(e) => return Err(dest_err(e)),
                }
                let restored =
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(car.mode))
                        .map_err(|e| io_fail("chmod", e))
                        .and_then(|_| chown(&dest, car.uid, car.gid));
                if let Err(e) = restored {
                    let _ = std::fs::remove_file(&dest);
                    return Err(e);
                }
                let _ = std::fs::remove_file(&vaulted);
                let _ = std::fs::remove_file(&sidecar_path);
                Ok(ExecDetail {
                    summary: format!("restored {}", dest.display()),
                    quarantine_id: Some(id),
                    sha256: Some(car.sha256.clone()),
                    signal: None,
                })
            })())
        }
    }

    fn dest_err(e: std::io::Error) -> ExecFailure {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            fail(FailCode::DestinationExists, "destination exists")
        } else {
            io_fail("restore", e)
        }
    }

    fn chown(path: &Path, uid: u32, gid: u32) -> Result<(), ExecFailure> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| fail(FailCode::Io, "path contains NUL"))?;
        // SAFETY: `c` is a valid NUL-terminated path for the call's duration.
        if unsafe { libc::chown(c.as_ptr(), uid, gid) } == 0 {
            Ok(())
        } else {
            Err(io_fail("chown", std::io::Error::last_os_error()))
        }
    }

    fn file_fd(f: &File) -> i32 {
        use std::os::unix::io::AsRawFd;
        f.as_raw_fd()
    }

    /// Cross-device move: copy from the checked open fd, sync, then unlink the
    /// original only if the path still names the same file.
    fn copy_across(
        file: &File,
        meta: &std::fs::Metadata,
        path: &str,
        vaulted: &Path,
    ) -> Result<(), ExecFailure> {
        let mut src = file;
        src.seek(SeekFrom::Start(0))
            .map_err(|e| io_fail("seek", e))?;
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(vaulted)
            .map_err(|e| io_fail("create vault file", e))?;
        let copied = std::io::copy(&mut src, &mut out).and_then(|_| out.sync_all());
        if let Err(e) = copied {
            let _ = std::fs::remove_file(vaulted);
            return Err(io_fail("copy into vault", e));
        }
        match std::fs::symlink_metadata(path) {
            Ok(now) if same_file(&now, meta) => std::fs::remove_file(path).map_err(|e| {
                let _ = std::fs::remove_file(vaulted);
                io_fail("unlink original", e)
            }),
            _ => {
                let _ = std::fs::remove_file(vaulted);
                Err(fail(FailCode::TargetChanged, "file swapped during move"))
            }
        }
    }
}

#[cfg(test)]
mod pure_tests {
    use super::*;

    const STAT: &str = "1234 (my (weird) proc) S 77 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 987654 12345678 300 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";

    #[test]
    fn stat_parsing_survives_odd_comm() {
        let s = parse_stat(STAT).unwrap();
        assert_eq!(s.state, 'S');
        assert_eq!(s.ppid, 77);
        assert_eq!(s.starttime_ticks, 987654);
    }

    #[test]
    fn stat_parsing_rejects_garbage() {
        assert!(parse_stat("").is_none());
        assert!(parse_stat("1 (x) S 1").is_none());
    }

    #[test]
    fn btime_and_start_ns() {
        assert_eq!(
            parse_btime("cpu 1 2\nbtime 1700000000\nprocs 3\n"),
            Some(1_700_000_000)
        );
        assert_eq!(parse_btime("cpu 1"), None);
        assert_eq!(start_ns(10, 250, 100), Some(12_500_000_000));
        assert_eq!(start_ns(10, 1, 0), None);
    }

    #[test]
    fn device_encoding() {
        assert_eq!(encode_dev(8, 1), (8u64 << 32) | 1);
        // st_dev of major 8, minor 1 is 0x801.
        assert_eq!(encode_st_dev(0x801), encode_dev(8, 1));
    }

    #[test]
    fn ancestor_chain_stops_at_root_and_cycles() {
        let parents = |p: u32| match p {
            300 => Some(200),
            200 => Some(100),
            100 => Some(1),
            1 => Some(0),
            _ => None,
        };
        assert_eq!(ancestors_from(300, parents), vec![200, 100, 1]);
        assert_eq!(ancestors_from(5, |_| Some(5)), Vec::<u32>::new());
        assert_eq!(
            ancestors_from(5, |p| Some(if p == 5 { 6 } else { 5 })),
            vec![6]
        );
    }

    #[test]
    fn sha256_and_sidecar_and_vault_paths() {
        assert_eq!(
            sha256_reader(&b"abc"[..]).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let id = Uuid::from_u128(9);
        let (f, s) = vault_paths(Path::new("/v"), id);
        assert_eq!(f, Path::new("/v").join(id.to_string()));
        assert_eq!(s, Path::new("/v").join(format!("{id}.json")));
        let car = Sidecar {
            path: "/a".into(),
            mode: 0o644,
            uid: 1,
            gid: 2,
            sha256: "x".into(),
            quarantined_at: 3,
        };
        let back: Sidecar = serde_json::from_slice(&serde_json::to_vec(&car).unwrap()).unwrap();
        assert_eq!(back, car);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_executor_fails_unsupported() {
        let e = default_executor(PathBuf::from("v"));
        assert_eq!(
            e.terminate(2, "/x", 0, false).unwrap_err().code,
            FailCode::Unsupported
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use osiris_command::ProtectedTargets;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::process::{Child, Command};

    fn now_ns() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    fn sleeper() -> (Child, String) {
        let child = Command::new("sleep").arg("60").spawn().unwrap();
        let exe = std::fs::read_link(format!("/proc/{}/exe", child.id())).unwrap();
        (child, exe.display().to_string())
    }

    fn exec(dir: &tempfile::TempDir) -> LinuxExecutor {
        LinuxExecutor {
            vault: dir.path().join("vault"),
        }
    }

    #[test]
    fn terminates_a_matching_process() {
        let dir = tempfile::tempdir().unwrap();
        let (mut child, exe) = sleeper();
        let r = exec(&dir)
            .terminate(child.id(), &exe, now_ns(), false)
            .unwrap();
        assert_eq!(r.signal.as_deref(), Some("SIGTERM"));
        assert!(child.wait().is_ok());
    }

    #[test]
    fn dry_run_leaves_the_process_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (mut child, exe) = sleeper();
        exec(&dir)
            .terminate(child.id(), &exe, now_ns(), true)
            .unwrap();
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn wrong_exe_path_is_target_changed_and_child_survives() {
        let dir = tempfile::tempdir().unwrap();
        let (mut child, _) = sleeper();
        let e = exec(&dir)
            .terminate(child.id(), "/bin/definitely-not-it", now_ns(), false)
            .unwrap_err();
        assert_eq!(e.code, FailCode::TargetChanged);
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn process_started_after_the_observation_is_target_changed() {
        let dir = tempfile::tempdir().unwrap();
        let (mut child, exe) = sleeper();
        let e = exec(&dir)
            .terminate(child.id(), &exe, 0, false)
            .unwrap_err();
        assert_eq!(e.code, FailCode::TargetChanged);
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn kernel_threads_and_missing_pids_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        // pid 2 is kthreadd; its exe link is unreadable.
        let e = exec(&dir).terminate(2, "/x", now_ns(), false).unwrap_err();
        assert_eq!(e.code, FailCode::Unverifiable);
        let e = exec(&dir)
            .terminate(u32::MAX - 1, "/x", now_ns(), false)
            .unwrap_err();
        assert!(matches!(
            e.code,
            FailCode::NotFound | FailCode::Unverifiable
        ));
    }

    fn ids(path: &Path) -> (u64, u64) {
        let m = std::fs::metadata(path).unwrap();
        (m.ino(), encode_st_dev(m.dev()))
    }

    #[test]
    fn quarantine_then_restore_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let ex = exec(&dir);
        let f = dir.path().join("evil.bin");
        std::fs::write(&f, b"payload").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        let (ino, dev) = ids(&f);
        let d = ex.quarantine(f.to_str().unwrap(), ino, dev, false).unwrap();
        let id = d.quarantine_id.unwrap();
        assert_eq!(
            d.sha256.as_deref(),
            Some(sha256_reader(&b"payload"[..]).unwrap().as_str())
        );
        assert!(!f.exists());
        let (vaulted, sidecar) = vault_paths(&ex.vault, id);
        assert_eq!(std::fs::metadata(&vaulted).unwrap().mode() & 0o7777, 0);
        let car: Sidecar = serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        assert_eq!(car.path, f.to_str().unwrap());
        assert_eq!(car.mode, 0o640);
        assert_eq!(std::fs::metadata(&ex.vault).unwrap().mode() & 0o777, 0o700);

        ex.restore(id, false).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"payload");
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o7777, 0o640);
        assert!(!vaulted.exists() && !sidecar.exists());
    }

    #[test]
    fn restore_refuses_when_destination_exists() {
        let dir = tempfile::tempdir().unwrap();
        let ex = exec(&dir);
        let f = dir.path().join("a.bin");
        std::fs::write(&f, b"one").unwrap();
        let (ino, dev) = ids(&f);
        let id = ex
            .quarantine(f.to_str().unwrap(), ino, dev, false)
            .unwrap()
            .quarantine_id
            .unwrap();
        std::fs::write(&f, b"new").unwrap();
        let e = ex.restore(id, false).unwrap_err();
        assert_eq!(e.code, FailCode::DestinationExists);
        assert_eq!(std::fs::read(&f).unwrap(), b"new");
    }

    #[test]
    fn swapped_inode_is_target_changed() {
        let dir = tempfile::tempdir().unwrap();
        let ex = exec(&dir);
        let f = dir.path().join("b.bin");
        std::fs::write(&f, b"x").unwrap();
        let (ino, dev) = ids(&f);
        let e = ex
            .quarantine(f.to_str().unwrap(), ino + 1, dev, false)
            .unwrap_err();
        assert_eq!(e.code, FailCode::TargetChanged);
        assert!(f.exists());
    }

    #[test]
    fn quarantine_dry_run_moves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let ex = exec(&dir);
        let f = dir.path().join("c.bin");
        std::fs::write(&f, b"x").unwrap();
        let (ino, dev) = ids(&f);
        ex.quarantine(f.to_str().unwrap(), ino, dev, true).unwrap();
        assert!(f.exists());
    }

    #[test]
    fn a_symlink_into_the_vault_is_refused_even_when_dangling() {
        let dir = tempfile::tempdir().unwrap();
        let ex = exec(&dir);
        crate::control::ensure_vault(&ex.vault).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(ex.vault.join("not-there-yet"), &link).unwrap();
        let e = ex
            .quarantine(link.to_str().unwrap(), 1, 1, false)
            .unwrap_err();
        assert_eq!(e.code, FailCode::TargetChanged);
    }

    #[test]
    fn a_path_resolving_into_the_vault_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ex = exec(&dir);
        let f = dir.path().join("d.bin");
        std::fs::write(&f, b"x").unwrap();
        let (ino, dev) = ids(&f);
        let id = ex
            .quarantine(f.to_str().unwrap(), ino, dev, false)
            .unwrap()
            .quarantine_id
            .unwrap();
        // A path that resolves into the vault (via a directory symlink).
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&ex.vault, &alias).unwrap();
        let via = alias.join(id.to_string());
        std::fs::set_permissions(
            vault_paths(&ex.vault, id).0,
            std::fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        let (i, d) = ids(&via);
        let e = ex
            .quarantine(via.to_str().unwrap(), i, d, false)
            .unwrap_err();
        assert_eq!(e.code, FailCode::TargetChanged);
    }

    #[test]
    fn guard_refuses_a_path_under_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let p = ProtectedTargets {
            agent_pid: 500,
            extra_pids: vec![],
            vault: dir.path().join("vault"),
        };
        assert!(p
            .check_path(dir.path().join("vault").join("x").to_str().unwrap())
            .is_err());
    }
}
