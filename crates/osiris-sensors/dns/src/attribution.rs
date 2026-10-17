//! Maps a DNS client's local UDP address to the owning process by joining
//! `/proc/net/udp{,6}` (address -> inode) with a cached `/proc/<pid>/fd`
//! scan (inode -> pid).

use crate::proc_udp::{parse_udp_table, UdpRow};
use crate::tracker::Attribution;
use osiris_sensors_net::fd_scan::{read_process_identity, scan_socket_inodes};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Minimum spacing between full fd rescans (Global Constraint #4).
const RESCAN_INTERVAL: Duration = Duration::from_millis(250);

pub struct Attributor {
    proc_root: PathBuf,
    inode_to_pid: HashMap<u64, u32>,
    last_scan: Option<Instant>,
}

impl Attributor {
    pub fn new(proc_root: PathBuf) -> Self {
        Self {
            proc_root,
            inode_to_pid: HashMap::new(),
            last_scan: None,
        }
    }

    fn read_rows(&self) -> Vec<UdpRow> {
        let mut rows = Vec::new();
        for (name, v6) in [("udp", false), ("udp6", true)] {
            if let Ok(text) = std::fs::read_to_string(self.proc_root.join("net").join(name)) {
                rows.extend(parse_udp_table(&text, v6));
            }
        }
        rows
    }

    /// Exact local address first, else a wildcard row on the same port
    /// (v4 wildcard, then v6 wildcard; dual-stack sockets appear in udp6).
    fn find_row(rows: &[UdpRow], client: SocketAddr) -> Option<&UdpRow> {
        let ip = client.ip().to_canonical();
        let port = client.port();
        let same_port = |r: &&UdpRow| r.local.port() == port;
        rows.iter()
            .filter(same_port)
            .find(|r| r.local.ip().to_canonical() == ip)
            .or_else(|| {
                rows.iter().filter(same_port).find(|r| {
                    matches!(r.local.ip(), IpAddr::V4(a) if a.is_unspecified()) && ip.is_ipv4()
                })
            })
            .or_else(|| {
                rows.iter()
                    .filter(same_port)
                    .find(|r| matches!(r.local.ip(), IpAddr::V6(a) if a.is_unspecified()))
            })
    }

    /// Attributes `client`. Failure yields `pid: None` with the uid from the
    /// UDP table when a row was found, else 0.
    pub fn lookup(&mut self, client: SocketAddr, now: Instant) -> Attribution {
        let rows = self.read_rows();
        let Some(row) = Self::find_row(&rows, client) else {
            return Attribution::default();
        };
        let (uid, inode) = (row.uid, row.inode);
        let mut found = self.inode_to_pid.get(&inode).copied();
        if found.is_none() && inode != 0 {
            let due = self
                .last_scan
                .is_none_or(|t| now.saturating_duration_since(t) >= RESCAN_INTERVAL);
            if due {
                self.inode_to_pid = scan_socket_inodes(&self.proc_root);
                self.last_scan = Some(now);
                found = self.inode_to_pid.get(&inode).copied();
            }
        }
        match found {
            Some(pid) => {
                let (exe_path, comm) = read_process_identity(&self.proc_root, pid);
                Attribution {
                    pid: Some(pid),
                    uid,
                    exe_path,
                    comm,
                }
            }
            None => Attribution {
                uid,
                ..Attribution::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const HDR: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n";

    fn row(local: &str, uid: u32, inode: u64) -> String {
        format!("  1: {local} 00000000:0000 07 00000000:00000000 00:00000000 00000000 {uid:5}        0 {inode} 2 0000000000000000 0\n")
    }

    fn write_net(root: &Path, udp: &str, udp6: &str) {
        let net = root.join("net");
        std::fs::create_dir_all(&net).unwrap();
        std::fs::write(net.join("udp"), format!("{HDR}{udp}")).unwrap();
        std::fs::write(net.join("udp6"), format!("{HDR}{udp6}")).unwrap();
    }

    /// Creates `<pid>/fd/3 -> socket:[inode]`, `exe` and `comm`. Returns
    /// false (test should skip) when symlinks cannot be created.
    fn add_process(root: &Path, pid: u32, inode: u64) -> bool {
        let dir = root.join(pid.to_string());
        std::fs::create_dir_all(dir.join("fd")).unwrap();
        std::fs::write(dir.join("comm"), "resolver\n").unwrap();
        if let Err(e) = make_symlink("/usr/bin/resolver", &dir.join("exe")) {
            eprintln!("skipping: cannot create symlinks here ({e})");
            return false;
        }
        make_symlink(&format!("socket:[{inode}]"), &dir.join("fd").join("3")).is_ok()
    }

    #[cfg(unix)]
    fn make_symlink(target: &str, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn make_symlink(target: &str, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }

    fn client() -> SocketAddr {
        "127.0.0.1:41000".parse().unwrap()
    }

    #[test]
    fn exact_bound_socket_matches() {
        let dir = tempfile::tempdir().unwrap();
        write_net(dir.path(), &row("0100007F:A028", 1000, 4242), "");
        if !add_process(dir.path(), 300, 4242) {
            return;
        }
        let a = Attributor::new(dir.path().to_path_buf()).lookup(client(), Instant::now());
        assert_eq!(a.pid, Some(300));
        assert_eq!(a.uid, 1000);
        assert_eq!(a.exe_path, "/usr/bin/resolver");
        assert_eq!(a.comm, "resolver");
    }

    #[test]
    fn wildcard_bound_socket_matches() {
        let dir = tempfile::tempdir().unwrap();
        write_net(dir.path(), &row("00000000:A028", 1000, 4242), "");
        if !add_process(dir.path(), 300, 4242) {
            return;
        }
        let a = Attributor::new(dir.path().to_path_buf()).lookup(client(), Instant::now());
        assert_eq!(a.pid, Some(300));
        assert_eq!(a.uid, 1000);
    }

    #[test]
    fn dual_stack_v6_wildcard_matches_v4_client() {
        let dir = tempfile::tempdir().unwrap();
        write_net(
            dir.path(),
            "",
            &row("00000000000000000000000000000000:A028", 7, 99),
        );
        let a = Attributor::new(dir.path().to_path_buf()).lookup(client(), Instant::now());
        assert_eq!(a.uid, 7);
    }

    #[test]
    fn unknown_port_is_unattributed() {
        let dir = tempfile::tempdir().unwrap();
        write_net(dir.path(), &row("00000000:0035", 1000, 4242), "");
        let a = Attributor::new(dir.path().to_path_buf()).lookup(client(), Instant::now());
        assert_eq!(a.pid, None);
        assert_eq!(a.uid, 0);
        assert_eq!(a, Attribution::default());
    }

    #[test]
    fn inode_without_pid_keeps_uid() {
        let dir = tempfile::tempdir().unwrap();
        write_net(dir.path(), &row("0100007F:A028", 1000, 4242), "");
        let a = Attributor::new(dir.path().to_path_buf()).lookup(client(), Instant::now());
        assert_eq!(a.pid, None);
        assert_eq!(a.uid, 1000);
        assert_eq!(a.exe_path, "");
        assert_eq!(a.comm, "");
    }

    #[test]
    fn rescan_rate_limited() {
        let dir = tempfile::tempdir().unwrap();
        write_net(dir.path(), &row("0100007F:A028", 1000, 4242), "");
        let mut at = Attributor::new(dir.path().to_path_buf());
        let t0 = Instant::now();
        assert_eq!(at.lookup(client(), t0).pid, None);
        if !add_process(dir.path(), 300, 4242) {
            return;
        }
        assert_eq!(
            at.lookup(client(), t0 + Duration::from_millis(100)).pid,
            None
        );
        assert_eq!(
            at.lookup(client(), t0 + Duration::from_millis(250)).pid,
            Some(300)
        );
    }
}
