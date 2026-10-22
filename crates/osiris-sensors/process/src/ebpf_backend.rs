//! eBPF record → raw event conversion (OS-neutral, so tested everywhere).
//!
//! The kernel side (`osiris-ebpf`'s `process` program) reports times on
//! two clocks: `ktime_ns` is `bpf_ktime_get_ns()` (CLOCK_MONOTONIC) and
//! `start_boottime_ns` is the task's boot-time start. Wall-clock
//! `timestamp_ns` is `ktime_ns` plus a realtime − monotonic offset the
//! sensor resamples for every record (so a wall-clock step or a suspend is
//! followed from the next record on); `start_time_mono` is the
//! boot-time start in clock ticks (USER_HZ 100), i.e. exactly what the
//! audit backend reads from `/proc/<pid>/stat` field 22, so both backends
//! derive the same `process_key` for one process.
//!
//! argv arrives as the raw NUL-separated `arg_start..arg_end` bytes
//! (bounded to 4096 by the BPF program); [`split_argv`] applies the audit
//! backend's caps ([`MAX_ARGS`], [`MAX_ARGV_BYTES`]) and keep-a-prefix rule
//! so downstream sees identical shapes from either backend.

use std::path::Path;

use osiris_ebpf::{decode_wait_status, resolve_exe, ExeIdentity, ExecEvent, ExitEvent};
use osiris_sensor_api::{ProcessExecRaw, ProcessExitRaw, RawEventSource};

use crate::execve::{MAX_ARGS, MAX_ARGV_BYTES};

/// Boot-time nanoseconds per clock tick at USER_HZ 100.
const NS_PER_CLOCK_TICK: u64 = 10_000_000;

/// Split raw argv bytes on NUL, like the audit backend's argv: one trailing
/// NUL terminates the last argument; a last fragment without one (argv cut
/// at the BPF bound) is kept; an empty argument between two NULs is kept
/// (audit logs it as `aI=""`); at most [`MAX_ARGS`] arguments and
/// [`MAX_ARGV_BYTES`] bytes are kept, the argument crossing the byte cap is
/// cut there and later ones are dropped. Non-UTF-8 bytes become U+FFFD.
pub fn split_argv(bytes: &[u8]) -> Vec<String> {
    if bytes.is_empty() {
        return vec![];
    }
    let body = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    let mut argv = Vec::new();
    let mut kept_bytes = 0usize;
    for arg in body.split(|&b| b == 0).take(MAX_ARGS) {
        let take = arg.len().min(MAX_ARGV_BYTES - kept_bytes);
        if take == 0 && !arg.is_empty() {
            // The byte cap is spent: audit drops this and every later one.
            break;
        }
        argv.push(String::from_utf8_lossy(&arg[..take]).into_owned());
        kept_bytes += take;
    }
    argv
}

/// Kernel boot-time start (ns) → `/proc/<pid>/stat` starttime (clock ticks).
pub fn start_time_ticks(start_boottime_ns: u64) -> u64 {
    start_boottime_ns / NS_PER_CLOCK_TICK
}

/// `ktime_ns` (CLOCK_MONOTONIC) → wall-clock ns, saturating into `u64`.
fn wall_clock_ns(ktime_ns: u64, boot_wall_offset_ns: i128) -> u64 {
    let wall = i128::from(ktime_ns) + boot_wall_offset_ns;
    wall.clamp(0, i128::from(u64::MAX)) as u64
}

/// The real procfs root used outside tests.
const PROC_ROOT: &str = "/proc";

/// `<proc_root>/<pid>/exe`'s target, when the process (and the link) still
/// exist.
fn proc_exe(proc_root: &Path, pid: u32) -> Option<String> {
    std::fs::read_link(proc_root.join(pid.to_string()).join("exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// The exec'd binary as the audit backend's `exe=` reports it: the
/// resolved `<proc_root>/<pid>/exe` link (symlinks such as `/bin/sh` →
/// `dash` followed; a script shows its interpreter) when it can be tied to
/// the record — by the kernel's exe identity, else by comm (see
/// [`osiris_ebpf::resolve_exe`]) — else the execve filename as given.
/// Detection rules key on `exe_path`, so both backends must agree.
pub fn resolve_exe_path(
    proc_root: &Path,
    pid: u32,
    exe: Option<ExeIdentity>,
    record_comm: &str,
    filename: &str,
) -> String {
    resolve_exe(proc_root, pid, exe, record_comm).unwrap_or_else(|| filename.to_string())
}

/// An exec record as the existing `ProcessExecRaw`; `exe_path` per
/// [`resolve_exe_path`] against `/proc`.
pub fn exec_to_raw(e: &ExecEvent, boot_wall_offset_ns: i128) -> ProcessExecRaw {
    let exe_path = resolve_exe_path(Path::new(PROC_ROOT), e.pid, e.exe, &e.comm, &e.filename);
    ProcessExecRaw {
        pid: e.pid,
        ppid: e.ppid,
        uid: e.uid,
        exe_path,
        comm: e.comm.clone(),
        cmdline: split_argv(&e.args),
        timestamp_ns: wall_clock_ns(e.ktime_ns, boot_wall_offset_ns),
        start_time_mono: start_time_ticks(e.start_boottime_ns),
        source: RawEventSource::Ebpf,
    }
}

/// An exit record as `ProcessExitRaw`; the wait status becomes
/// `exit_code` (normal exit) or `signal` (killed). `exe_path` is
/// best-effort: `/proc/<pid>/exe` if still readable, else empty.
pub fn exit_to_raw(e: &ExitEvent, boot_wall_offset_ns: i128) -> ProcessExitRaw {
    let (exit_code, signal) = decode_wait_status(e.exit_status);
    ProcessExitRaw {
        pid: e.pid,
        ppid: e.ppid,
        uid: e.uid,
        comm: e.comm.clone(),
        exe_path: proc_exe(Path::new(PROC_ROOT), e.pid).unwrap_or_default(),
        exit_code,
        signal,
        timestamp_ns: wall_clock_ns(e.ktime_ns, boot_wall_offset_ns),
        start_time_mono: start_time_ticks(e.start_boottime_ns),
        source: RawEventSource::Ebpf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_bytes_split_like_audit() {
        assert_eq!(split_argv(b"ls\0-la\0/tmp\0"), ["ls", "-la", "/tmp"]);
        // Cut at the BPF bound: no trailing NUL, the last fragment is kept.
        assert_eq!(split_argv(b"ls\0-la\0/tm"), ["ls", "-la", "/tm"]);
        assert_eq!(split_argv(b""), Vec::<String>::new());
        // Audit keeps an empty middle argument (`a1=""`), so do we.
        assert_eq!(split_argv(b"x\0\0y\0"), ["x", "", "y"]);
        // Same caps as execve.rs.
        let many: Vec<u8> = (0..MAX_ARGS + 5)
            .flat_map(|i| format!("{i}\0").into_bytes())
            .collect();
        let argv = split_argv(&many);
        assert_eq!(argv.len(), MAX_ARGS);
        assert_eq!(argv[MAX_ARGS - 1], (MAX_ARGS - 1).to_string());
        let mut big = vec![b'x'; MAX_ARGV_BYTES - 2];
        big.extend_from_slice(b"\0abcd\0efgh\0");
        let argv = split_argv(&big);
        assert_eq!(argv.len(), 2);
        assert_eq!(argv[1], "ab");
        // Invalid UTF-8 is replaced, not dropped.
        assert_eq!(split_argv(b"A\xffB\0"), ["A\u{FFFD}B"]);
    }

    fn exec_event() -> ExecEvent {
        ExecEvent {
            // No such pid, so /proc/<pid>/exe is unreadable on any host.
            pid: u32::MAX,
            ppid: 1,
            uid: 1000,
            ktime_ns: 5_000_000_000,
            start_boottime_ns: 12_340_000_000,
            comm: "ls".to_string(),
            filename: "/usr/bin/ls".to_string(),
            args: b"ls\0-la\0".to_vec(),
            args_truncated: false,
            exe: None,
        }
    }

    #[test]
    fn exec_conversion() {
        let raw = exec_to_raw(&exec_event(), 1_700_000_000_000_000_000);
        assert_eq!(raw.start_time_mono, 1234);
        assert_eq!(raw.timestamp_ns, 1_700_000_005_000_000_000);
        assert_eq!(raw.source, RawEventSource::Ebpf);
        assert_eq!(raw.pid, u32::MAX);
        assert_eq!(raw.ppid, 1);
        assert_eq!(raw.uid, 1000);
        assert_eq!(raw.comm, "ls");
        assert_eq!(raw.exe_path, "/usr/bin/ls");
        assert_eq!(raw.cmdline, ["ls", "-la"]);
    }

    #[test]
    fn exec_conversion_keeps_a_relative_filename_when_proc_is_unreadable() {
        let mut e = exec_event();
        e.pid = u32::MAX; // no such process
        e.filename = "./run.sh".to_string();
        assert_eq!(exec_to_raw(&e, 0).exe_path, "./run.sh");
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

    /// Like audit's `exe=`, a readable `/proc/<pid>/exe` wins over the
    /// execve filename (even an absolute one: `/bin/sh` → `dash`) while
    /// `/proc/<pid>/comm` still matches the record's comm.
    #[test]
    fn resolved_proc_exe_wins_over_the_filename() {
        let Some((root, target)) = fake_proc(b"sh\n") else {
            return;
        };
        assert_eq!(
            resolve_exe_path(root.path(), 77, None, "sh", "/bin/sh"),
            target.to_string_lossy()
        );
    }

    /// `sh -c 'curl …'` execs curl in place before the `/bin/sh` record is
    /// consumed: the link now names curl's image and comm says `curl`, so
    /// the `/bin/sh` event keeps its own execve filename.
    #[test]
    fn a_later_exec_is_detected_by_comm_and_the_filename_is_kept() {
        let Some((root, _target)) = fake_proc(b"curl\n") else {
            return;
        };
        assert_eq!(
            resolve_exe_path(root.path(), 77, None, "sh", "/bin/sh"),
            "/bin/sh"
        );
    }

    #[test]
    fn filename_is_used_when_proc_exe_is_unreadable() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_exe_path(root.path(), 77, None, "sh", "/bin/sh"),
            "/bin/sh"
        );
        assert_eq!(
            resolve_exe_path(root.path(), 77, None, "run.sh", "./run.sh"),
            "./run.sh"
        );
    }

    #[test]
    fn exit_conversion_signal() {
        let e = ExitEvent {
            pid: u32::MAX,
            ppid: 1,
            uid: 0,
            exit_status: 9,
            ktime_ns: 10,
            start_boottime_ns: 12_340_000_000,
            comm: "sleep".to_string(),
        };
        let raw = exit_to_raw(&e, -5);
        assert_eq!(raw.signal, Some(9));
        assert_eq!(raw.exit_code, None);
        assert_eq!(raw.timestamp_ns, 5);
        assert_eq!(raw.start_time_mono, 1234);
        assert_eq!(raw.exe_path, "");
        assert_eq!(raw.source, RawEventSource::Ebpf);

        let normal = exit_to_raw(
            &ExitEvent {
                exit_status: 7 << 8,
                ..e
            },
            0,
        );
        assert_eq!(normal.exit_code, Some(7));
        assert_eq!(normal.signal, None);
    }
}
