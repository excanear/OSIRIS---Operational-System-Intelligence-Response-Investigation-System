use std::collections::HashMap;
use std::path::PathBuf;

use osiris_sensor_api::{NetworkDirection, NetworkEventRaw, NetworkOperation, RawEventSource};

use crate::fd_scan::scan_socket_inodes;
use crate::proc_tcp::{parse_tcp_table, TCP_ESTABLISHED};

/// A local Linux ephemeral-port floor (Phase 3 plan Global Constraints #4).
/// A connection whose local port is at or above this is treated as this
/// host having dialed out; below it, as this host answering on a
/// known/listening port. Documented heuristic, not ground truth.
const EPHEMERAL_PORT_FLOOR: u16 = 32768;

#[derive(Clone, PartialEq, Eq, Hash)]
struct ConnTuple {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
}

#[derive(Clone)]
struct ConnRecord {
    direction: NetworkDirection,
    pid: Option<u32>,
    uid: u32,
    exe_path: String,
    comm: String,
}

/// Polls a `/proc`-shaped directory tree for TCP connection lifecycle
/// changes (ARCHITECTURE.md §4.3's Network fallback backend, Phase 3 plan
/// Global Constraints #1). `proc_root` is configurable — a real deployment
/// points it at `/proc`; tests point it at a tempdir fixture — the same
/// "the real path is configurable, defaults sensible for real deployment"
/// pattern Phase 1/2 established for the audit log path.
pub struct NetworkPoller {
    proc_root: PathBuf,
    previous: HashMap<ConnTuple, ConnRecord>,
}

impl NetworkPoller {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            previous: HashMap::new(),
        }
    }

    /// One poll tick: reads the current `net/tcp` snapshot, diffs it
    /// against the previous tick, and returns every connection-lifecycle
    /// event observed. A missing/unreadable `net/tcp` yields an empty
    /// `Vec`, not an error — callers treat "nothing to report" as normal,
    /// matching `LineTailer::poll`'s contract from Phase 1/2.
    pub fn poll(&mut self, now_ns: u64) -> Vec<NetworkEventRaw> {
        let tcp_path = self.proc_root.join("net").join("tcp");
        let Ok(text) = std::fs::read_to_string(&tcp_path) else {
            return vec![];
        };
        let inode_to_pid = scan_socket_inodes(&self.proc_root);

        let mut current: HashMap<ConnTuple, u64> = HashMap::new(); // tuple -> inode
        let mut current_meta: HashMap<ConnTuple, (u16, u32)> = HashMap::new(); // tuple -> (local_port, uid)
        for row in parse_tcp_table(&text) {
            if row.state != TCP_ESTABLISHED {
                continue;
            }
            let tuple = ConnTuple {
                local_addr: row.local_addr.clone(),
                local_port: row.local_port,
                remote_addr: row.remote_addr.clone(),
                remote_port: row.remote_port,
            };
            current_meta.insert(tuple.clone(), (row.local_port, row.uid));
            current.insert(tuple, row.inode);
        }

        let mut events = Vec::new();

        // New connections: present now, absent from the previous snapshot.
        for (tuple, inode) in &current {
            if self.previous.contains_key(tuple) {
                continue;
            }
            let (local_port, uid) = current_meta[tuple];
            let direction = if local_port >= EPHEMERAL_PORT_FLOOR {
                NetworkDirection::Outbound
            } else {
                NetworkDirection::Inbound
            };
            let operation = match direction {
                NetworkDirection::Outbound => NetworkOperation::Connect,
                NetworkDirection::Inbound => NetworkOperation::Accept,
            };
            let pid = inode_to_pid.get(inode).copied();
            let (exe_path, comm) = pid
                .map(|p| crate::fd_scan::read_process_identity(&self.proc_root, p))
                .unwrap_or_default();

            events.push(NetworkEventRaw {
                operation,
                local_addr: tuple.local_addr.clone(),
                local_port: tuple.local_port,
                remote_addr: tuple.remote_addr.clone(),
                remote_port: tuple.remote_port,
                proto: "tcp".to_string(),
                direction,
                pid,
                uid,
                exe_path: exe_path.clone(),
                comm: comm.clone(),
                timestamp_ns: now_ns,
                source: RawEventSource::Audit,
            });
            self.previous.insert(
                tuple.clone(),
                ConnRecord {
                    direction,
                    pid,
                    uid,
                    exe_path,
                    comm,
                },
            );
        }

        // Closed connections: present in the previous snapshot, absent now.
        let closed: Vec<ConnTuple> = self
            .previous
            .keys()
            .filter(|tuple| !current.contains_key(*tuple))
            .cloned()
            .collect();
        for tuple in closed {
            let record = self.previous.remove(&tuple).expect("just checked present");
            events.push(NetworkEventRaw {
                operation: NetworkOperation::Close,
                local_addr: tuple.local_addr,
                local_port: tuple.local_port,
                remote_addr: tuple.remote_addr,
                remote_port: tuple.remote_port,
                proto: "tcp".to_string(),
                direction: record.direction,
                pid: record.pid,
                uid: record.uid,
                exe_path: record.exe_path,
                comm: record.comm,
                timestamp_ns: now_ns,
                source: RawEventSource::Audit,
            });
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::{NetworkDirection, NetworkOperation};

    /// Writes a minimal fake `<proc_root>/net/tcp` with exactly the rows the
    /// caller lists (`(local_port, remote_addr_hex, remote_port_hex, state,
    /// uid, inode)`), matching real `/proc/net/tcp` column layout.
    fn write_tcp_table(proc_root: &std::path::Path, rows: &[(u16, &str, u16, u8, u32, u64)]) {
        std::fs::create_dir_all(proc_root.join("net")).unwrap();
        let mut text = String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        );
        for (i, (local_port, remote_addr, remote_port, state, uid, inode)) in
            rows.iter().enumerate()
        {
            text.push_str(&format!(
                "  {i}: 0500000A:{local_port:04X} {remote_addr}:{remote_port:04X} {state:02X} 00000000:00000000 00:00000000 00000000 {uid:5} 0 {inode} 1 0 100 0 0 10 0\n"
            ));
        }
        std::fs::write(proc_root.join("net").join("tcp"), text).unwrap();
    }

    const REMOTE_HEX: &str = "32671BCB"; // decodes to 203.27.103.50, matching proc_tcp's tests

    #[test]
    fn a_new_established_connection_on_an_ephemeral_port_emits_connect() {
        let dir = tempfile::tempdir().unwrap();
        write_tcp_table(dir.path(), &[(51000, REMOTE_HEX, 443, 0x01, 1000, 12345)]);
        let mut poller = NetworkPoller::new(dir.path());

        let events = poller.poll(1_000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, NetworkOperation::Connect);
        assert_eq!(events[0].direction, NetworkDirection::Outbound);
        assert_eq!(events[0].remote_addr, "203.27.103.50");
        assert_eq!(events[0].remote_port, 443);
        assert_eq!(events[0].uid, 1000);
        assert_eq!(events[0].pid, None, "no /proc/<pid>/fd tree exists in this fixture");
    }

    #[test]
    fn a_new_established_connection_on_a_well_known_local_port_emits_accept() {
        let dir = tempfile::tempdir().unwrap();
        write_tcp_table(dir.path(), &[(22, REMOTE_HEX, 51500, 0x01, 0, 22222)]);
        let mut poller = NetworkPoller::new(dir.path());

        let events = poller.poll(1_000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, NetworkOperation::Accept);
        assert_eq!(events[0].direction, NetworkDirection::Inbound);
    }

    #[test]
    fn a_listen_row_state_0a_is_never_reported_as_a_connection() {
        let dir = tempfile::tempdir().unwrap();
        write_tcp_table(dir.path(), &[(22, "00000000", 0, 0x0A, 0, 99999)]);
        let mut poller = NetworkPoller::new(dir.path());
        assert_eq!(poller.poll(1_000).len(), 0);
    }

    #[test]
    fn a_steady_state_connection_present_in_two_consecutive_polls_emits_nothing_the_second_time() {
        let dir = tempfile::tempdir().unwrap();
        write_tcp_table(dir.path(), &[(51000, REMOTE_HEX, 443, 0x01, 1000, 12345)]);
        let mut poller = NetworkPoller::new(dir.path());
        assert_eq!(poller.poll(1_000).len(), 1); // the open event

        // Unchanged snapshot on the second poll.
        assert_eq!(poller.poll(2_000).len(), 0);
    }

    #[test]
    fn a_connection_that_disappears_between_polls_emits_close_with_the_original_direction() {
        let dir = tempfile::tempdir().unwrap();
        write_tcp_table(dir.path(), &[(51000, REMOTE_HEX, 443, 0x01, 1000, 12345)]);
        let mut poller = NetworkPoller::new(dir.path());
        let opened = poller.poll(1_000);
        assert_eq!(opened[0].operation, NetworkOperation::Connect);

        write_tcp_table(dir.path(), &[]); // the connection is gone
        let closed = poller.poll(2_000);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].operation, NetworkOperation::Close);
        assert_eq!(closed[0].remote_addr, "203.27.103.50");
        assert_eq!(
            closed[0].direction,
            NetworkDirection::Outbound,
            "close must reuse the direction recorded when the connection opened, not \
             re-evaluate a heuristic against data that's gone"
        );
        assert_eq!(closed[0].timestamp_ns, 2_000);
    }

    #[test]
    fn a_missing_proc_net_tcp_file_yields_no_events_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        // No net/tcp written at all.
        let mut poller = NetworkPoller::new(dir.path());
        assert_eq!(poller.poll(1_000).len(), 0);
    }

    #[test]
    fn two_distinct_connections_in_one_snapshot_both_get_reported() {
        let dir = tempfile::tempdir().unwrap();
        write_tcp_table(
            dir.path(),
            &[
                (51000, REMOTE_HEX, 443, 0x01, 1000, 12345),
                (22, REMOTE_HEX, 51500, 0x01, 0, 22222),
            ],
        );
        let mut poller = NetworkPoller::new(dir.path());
        let events = poller.poll(1_000);
        assert_eq!(events.len(), 2);
    }
}
