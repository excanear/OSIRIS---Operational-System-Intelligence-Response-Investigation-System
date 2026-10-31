//! eBPF DNS send record → [`KernelSend`] conversion (OS-neutral, so tested
//! everywhere), plus the agent's own network namespace inode.
//!
//! The kernel side (`osiris-ebpf`'s `dns` program) emits one record per UDP
//! send to port 53. The reader thread converts each record as soon as it is
//! read: the exe is resolved immediately, while the sender is almost
//! certainly still alive, and `ktime_ns` (CLOCK_MONOTONIC) becomes wall
//! time with a realtime − monotonic offset resampled for every record.

use std::path::Path;

use osiris_ebpf::{resolve_exe, DnsSendEvent};

use crate::send_table::{KernelSend, SendKey};
use crate::tracker::Attribution;

/// `ktime_ns` (CLOCK_MONOTONIC) → wall-clock ns, clamped into `u64`.
fn wall_clock_ns(ktime_ns: u64, boot_wall_offset_ns: i128) -> u64 {
    let wall = i128::from(ktime_ns) + boot_wall_offset_ns;
    wall.clamp(0, i128::from(u64::MAX)) as u64
}

/// One decoded DNS send as a [`SendTable`](crate::send_table::SendTable)
/// entry. `exe_path` is the `<proc_root>/<pid>/exe` link when
/// [`resolve_exe`] can tie it to the record, else `""`.
pub fn send_from_event(
    e: &DnsSendEvent,
    boot_wall_offset_ns: i128,
    proc_root: &Path,
) -> KernelSend {
    let exe_path = resolve_exe(proc_root, e.pid, e.exe, &e.comm).unwrap_or_default();
    KernelSend {
        key: SendKey::new(e.local, e.remote),
        laddr: e.local.ip(),
        sent_wall_ns: wall_clock_ns(e.ktime_ns, boot_wall_offset_ns),
        owner: Attribution {
            pid: Some(e.pid),
            uid: e.uid,
            exe_path,
            comm: e.comm.clone(),
        },
    }
}

/// Inode of the agent's network namespace (`stat("/proc/self/ns/net")`),
/// truncated to the kernel's 32-bit `ns.inum`; `None` when unreadable or
/// off Linux (GC 8: eBPF attribution is then unusable).
pub fn agent_netns_ino() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self/ns/net")
            .ok()
            .map(|m| m.ino() as u32)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn event() -> DnsSendEvent {
        DnsSendEvent {
            pid: 4321,
            tid: 4322,
            uid: 1000,
            ktime_ns: 5_000_000_000,
            comm: "dig".to_string(),
            exe: None,
            netns_ino: 4026531840,
            local: SocketAddr::from(([10, 0, 0, 2], 41000)),
            remote: SocketAddr::from(([10, 0, 0, 1], 53)),
        }
    }

    #[test]
    fn send_from_event_maps_fields() {
        let proc_root = tempfile::tempdir().unwrap();
        let e = event();
        let send = send_from_event(&e, 1_700_000_000_000_000_000, proc_root.path());
        assert_eq!(send.owner.pid, Some(4321));
        assert_eq!(send.owner.uid, 1000);
        assert_eq!(send.owner.comm, "dig");
        assert_eq!(send.owner.exe_path, "");
        assert_eq!(send.sent_wall_ns, 1_700_000_005_000_000_000);
        assert_eq!(send.key, SendKey::new(e.local, e.remote));
        assert_eq!(send.key.lport, 41000);
        assert_eq!(send.key.rport, 53);
        assert_eq!(send.key.raddr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(send.laddr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn send_time_is_clamped_at_zero() {
        let proc_root = tempfile::tempdir().unwrap();
        let send = send_from_event(&event(), -10_000_000_000, proc_root.path());
        assert_eq!(send.sent_wall_ns, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn agent_netns_ino_is_readable_on_linux() {
        assert!(agent_netns_ino().is_some_and(|ino| ino != 0));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn agent_netns_ino_is_none_off_linux() {
        assert_eq!(agent_netns_ino(), None);
    }
}
