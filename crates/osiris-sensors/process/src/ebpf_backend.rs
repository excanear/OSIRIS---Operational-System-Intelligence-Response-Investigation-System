//! eBPF record → raw event conversion (OS-neutral, so tested everywhere).
//!
//! The kernel side (`osiris-ebpf`'s `process` program) reports times on
//! two clocks: `ktime_ns` is `bpf_ktime_get_ns()` (CLOCK_MONOTONIC) and
//! `start_boottime_ns` is the task's boot-time start. Wall-clock
//! `timestamp_ns` is `ktime_ns` plus a realtime − monotonic offset the
//! sensor samples once when its reader starts; `start_time_mono` is the
//! boot-time start in clock ticks (USER_HZ 100), i.e. exactly what the
//! audit backend reads from `/proc/<pid>/stat` field 22, so both backends
//! derive the same `process_key` for one process.
//!
//! argv arrives as the raw NUL-separated `arg_start..arg_end` bytes
//! (bounded to 4096 by the BPF program); [`split_argv`] applies the audit
//! backend's caps ([`MAX_ARGS`], [`MAX_ARGV_BYTES`]) and keep-a-prefix rule
//! so downstream sees identical shapes from either backend.

use osiris_ebpf::{decode_wait_status, ExecEvent, ExitEvent};
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

/// `/proc/<pid>/exe`'s target, when the process (and the link) still exist.
fn proc_exe(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// An exec record as the existing `ProcessExecRaw`. `exe_path` is the
/// exec'd filename when absolute, else `/proc/<pid>/exe`'s target when
/// readable, else the filename as given.
pub fn exec_to_raw(e: &ExecEvent, boot_wall_offset_ns: i128) -> ProcessExecRaw {
    let exe_path = if e.filename.starts_with('/') {
        e.filename.clone()
    } else {
        proc_exe(e.pid).unwrap_or_else(|| e.filename.clone())
    };
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
        exe_path: proc_exe(e.pid).unwrap_or_default(),
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
            pid: 4242,
            ppid: 1,
            uid: 1000,
            ktime_ns: 5_000_000_000,
            start_boottime_ns: 12_340_000_000,
            comm: "ls".to_string(),
            filename: "/usr/bin/ls".to_string(),
            args: b"ls\0-la\0".to_vec(),
            args_truncated: false,
        }
    }

    #[test]
    fn exec_conversion() {
        let raw = exec_to_raw(&exec_event(), 1_700_000_000_000_000_000);
        assert_eq!(raw.start_time_mono, 1234);
        assert_eq!(raw.timestamp_ns, 1_700_000_005_000_000_000);
        assert_eq!(raw.source, RawEventSource::Ebpf);
        assert_eq!(raw.pid, 4242);
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
