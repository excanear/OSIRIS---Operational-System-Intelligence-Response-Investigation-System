use serde::{Deserialize, Serialize};

/// Where a raw record originated — carried through to CanonicalEvent.source
/// during normalization (ARCHITECTURE.md §9.2's `source` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawEventSource {
    Audit,
    Synthetic,
}

/// A Process/Exec creation record at MINIMAL telemetry (ARCHITECTURE.md §6:
/// "create/exit, pid/ppid/uid/exe" — no argv/env at this level).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExecRaw {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exe_path: String,
    pub comm: String,
    /// Wall-clock nanoseconds, UTC, from the originating backend.
    pub timestamp_ns: u64,
    /// Best-effort process start time for process_key hashing
    /// (ARCHITECTURE.md §9.2). Falls back to `timestamp_ns` when the real
    /// monotonic start time (e.g. /proc/<pid>/stat's starttime) isn't
    /// available.
    pub start_time_mono: u64,
    pub source: RawEventSource,
}

/// The four filesystem operations this phase emits — ARCHITECTURE.md §6's
/// Filesystem STANDARD row ("create/delete/rename on watched paths") plus
/// write, which the audit backend yields from the same PATH records. No
/// read, permission, owner, or attribute operations: those are §6's
/// DETAILED/FORENSIC rungs (Phase 2 plan Global Constraints #5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOperation {
    Create,
    Write,
    Delete,
    Rename,
}

/// A filesystem operation record. Unlike `ProcessExecRaw` this is assembled
/// from *several* correlated audit records (one `type=SYSCALL` supplying the
/// acting process fields, one `type=PATH` supplying the file fields, and
/// optionally one `type=CWD` used to absolutize a relative path), so every
/// field here is already joined and absolute by the time a sensor emits it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEventRaw {
    pub operation: FileOperation,
    /// Absolute path. For `Rename` this is the *destination* path.
    ///
    /// KNOWN LIMITATION (audit backend): a relative `name=` from a `*at()`
    /// syscall (`openat`, `unlinkat`, `renameat`, ...) called with a real
    /// (non-`AT_FDCWD`) dirfd is resolved against the group's process-CWD
    /// record, not the directory the dirfd actually named — audit's
    /// `type=PATH` records don't carry enough information to recover that
    /// directory. This can produce a confidently absolute but wrong path
    /// (see `osiris_sensors_fs::assembler::absolutize`'s doc comment). The
    /// `inode`/`device_id` identity below is unaffected, so identity-based
    /// joins (File Story) remain correct even when `path` isn't.
    pub path: String,
    /// Only set for `Rename`: the source path the file moved from.
    pub previous_path: Option<String>,
    /// Inode and device of the file itself. `None` when the backend could
    /// not report them (an audit PATH record omits them for some
    /// `nametype=UNKNOWN` items) — the pipeline then emits no entity-graph
    /// edge rather than inventing an identity.
    pub inode: Option<u64>,
    /// See `osiris_schema::encode_device_id` for the encoding.
    pub device_id: Option<u64>,
    pub mode: Option<u32>,
    pub owner_uid: Option<u32>,
    pub owner_gid: Option<u32>,
    /// The acting process, from the group's `type=SYSCALL` record.
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exe_path: String,
    pub comm: String,
    /// Wall-clock nanoseconds, UTC, from the audit event header.
    pub timestamp_ns: u64,
    /// The originating audit event's serial, retained for provenance so an
    /// operator can find the exact record group in the source log.
    pub audit_serial: Option<u64>,
    pub source: RawEventSource,
}

/// The three connection lifecycle events this phase emits — ARCHITECTURE.md
/// §6's Network STANDARD row ("connect/accept/close, 5-tuple"). No
/// SOCKET_CREATE/BIND/LISTEN this phase (Phase 3 plan Global Constraints
/// #3) — a listening socket's own lifecycle needs finer-grained state
/// tracking than one poll-interval diff reliably distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkOperation {
    Connect,
    Accept,
    Close,
}

/// Which side of the connection this host is. Derived from a documented
/// port-range heuristic, not ground truth (Phase 3 plan Global Constraints
/// #4) — `/proc/net/tcp` alone does not report which side initiated a
/// connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDirection {
    Inbound,
    Outbound,
}

/// A TCP connection lifecycle record, assembled from a `/proc/net/tcp`
/// snapshot diff plus a best-effort `/proc/<pid>/fd` inode scan for process
/// attribution (Phase 3 plan Global Constraints #1/#5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEventRaw {
    pub operation: NetworkOperation,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    /// Always `"tcp"` this phase (IPv4-only, Global Constraints #1/#2) —
    /// kept as a string rather than an enum so a later UDP/IPv6 backend
    /// extends this field's value set without a breaking type change.
    pub proto: String,
    pub direction: NetworkDirection,
    /// `None` when the sensor could not attribute this connection to a
    /// process (Global Constraint #5) — the pipeline then emits no
    /// `process` and no `CONNECTED_TO` edge, rather than guessing.
    pub pid: Option<u32>,
    /// Always populated directly from the `/proc/net/tcp` row's `uid`
    /// column, independent of whether pid attribution succeeded.
    pub uid: u32,
    /// Empty when `pid` is `None`, or when `pid` resolved but
    /// `/proc/<pid>/exe`/`/proc/<pid>/comm` could not be read (the process
    /// may have exited between the fd-scan and the read).
    pub exe_path: String,
    pub comm: String,
    /// Wall-clock nanoseconds, UTC, from the sensor's own clock at the poll
    /// tick this connection's state change was observed (`/proc/net/tcp`
    /// carries no per-connection timestamp of its own).
    pub timestamp_ns: u64,
    pub source: RawEventSource,
}

/// A DNS query+response record (ARCHITECTURE.md §6's DNS STANDARD row:
/// "query+response on watched resolvers"). No live sensor emits this raw
/// shape in this phase (Phase 3 plan Global Constraints #6) — it exists so
/// the full pipeline is real and tested via the Synthetic sensor ahead of a
/// later phase's real backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEventRaw {
    pub query: String,
    /// DNS record type queried, e.g. `"A"`, `"AAAA"`, `"CNAME"`.
    pub qtype: String,
    /// Empty when the query did not resolve (NXDOMAIN, timeout) — still a
    /// valid, storable `DNS_QUERY` event; `dns.response_ips` being empty is
    /// itself sometimes the interesting signal.
    pub response_ips: Vec<String>,
    pub ttl: Option<u32>,
    /// Same best-effort-attribution shape as `NetworkEventRaw` — a real
    /// pcap/eBPF DNS backend has the same "who asked" attribution problem
    /// a passive capture faces without also correlating process state.
    pub pid: Option<u32>,
    pub uid: u32,
    pub exe_path: String,
    pub comm: String,
    pub timestamp_ns: u64,
    pub source: RawEventSource,
}

/// The shape sensors emit onto their output channel (ARCHITECTURE.md §7.1
/// step 1, "Collect"). Phase 1 scoped this to Process/Exec; Phase 2 adds
/// File. Later phases add Network/Dns/... variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RawEvent {
    ProcessExec(ProcessExecRaw),
    File(FileEventRaw),
    Network(NetworkEventRaw),
    Dns(DnsEventRaw),
}

impl RawEvent {
    /// The originating backend's wall-clock timestamp, regardless of
    /// variant — used by sensors for their `last_event_at` health field
    /// without matching on the variant at every call site.
    pub fn timestamp_ns(&self) -> u64 {
        match self {
            RawEvent::ProcessExec(p) => p.timestamp_ns,
            RawEvent::File(f) => f.timestamp_ns,
            RawEvent::Network(n) => n.timestamp_ns,
            RawEvent::Dns(d) => d.timestamp_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_raw() -> FileEventRaw {
        FileEventRaw {
            operation: FileOperation::Create,
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode: Some(131075),
            device_id: Some((8u64 << 32) | 1),
            mode: Some(0o100644),
            owner_uid: Some(33),
            owner_gid: Some(33),
            pid: 300,
            ppid: 200,
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_690_000_000_123_000_000,
            audit_serial: Some(456),
            source: RawEventSource::Audit,
        }
    }

    #[test]
    fn file_raw_round_trips_through_json() {
        let raw = RawEvent::File(file_raw());
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::File(f) => {
                assert_eq!(f.path, "/var/www/html/shell.php");
                assert_eq!(f.operation, FileOperation::Create);
                assert_eq!(f.inode, Some(131075));
            }
            other => panic!("expected RawEvent::File, got {other:?}"),
        }
    }

    #[test]
    fn timestamp_accessor_works_for_both_variants() {
        assert_eq!(
            RawEvent::File(file_raw()).timestamp_ns(),
            1_690_000_000_123_000_000
        );
        let exec = RawEvent::ProcessExec(ProcessExecRaw {
            pid: 1,
            ppid: 0,
            uid: 0,
            exe_path: "/bin/init".to_string(),
            comm: "init".to_string(),
            timestamp_ns: 42,
            start_time_mono: 42,
            source: RawEventSource::Synthetic,
        });
        assert_eq!(exec.timestamp_ns(), 42);
    }

    fn network_raw() -> NetworkEventRaw {
        NetworkEventRaw {
            operation: NetworkOperation::Connect,
            local_addr: "10.0.0.5".to_string(),
            local_port: 51000,
            remote_addr: "203.0.113.50".to_string(),
            remote_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            pid: Some(300),
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_690_000_005_000_000_000,
            source: RawEventSource::Synthetic,
        }
    }

    fn dns_raw() -> DnsEventRaw {
        DnsEventRaw {
            query: "cdn-assets.xyz".to_string(),
            qtype: "A".to_string(),
            response_ips: vec!["203.0.113.50".to_string()],
            ttl: Some(300),
            pid: Some(300),
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_690_000_004_000_000_000,
            source: RawEventSource::Synthetic,
        }
    }

    #[test]
    fn network_raw_round_trips_through_json() {
        let raw = RawEvent::Network(network_raw());
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Network(n) => {
                assert_eq!(n.remote_addr, "203.0.113.50");
                assert_eq!(n.operation, NetworkOperation::Connect);
                assert_eq!(n.pid, Some(300));
            }
            other => panic!("expected RawEvent::Network, got {other:?}"),
        }
    }

    #[test]
    fn dns_raw_round_trips_through_json() {
        let raw = RawEvent::Dns(dns_raw());
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Dns(d) => {
                assert_eq!(d.query, "cdn-assets.xyz");
                assert_eq!(d.response_ips, vec!["203.0.113.50".to_string()]);
            }
            other => panic!("expected RawEvent::Dns, got {other:?}"),
        }
    }

    #[test]
    fn timestamp_accessor_works_for_network_and_dns_variants() {
        assert_eq!(
            RawEvent::Network(network_raw()).timestamp_ns(),
            1_690_000_005_000_000_000
        );
        assert_eq!(
            RawEvent::Dns(dns_raw()).timestamp_ns(),
            1_690_000_004_000_000_000
        );
    }

    /// A connection the sensor could not attribute to a pid (Global
    /// Constraint #5) still round-trips — `pid: None` must not break
    /// (de)serialization.
    #[test]
    fn network_raw_with_no_pid_attribution_round_trips() {
        let mut raw = network_raw();
        raw.pid = None;
        raw.exe_path = String::new();
        raw.comm = String::new();
        let json = serde_json::to_string(&RawEvent::Network(raw)).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Network(n) => assert_eq!(n.pid, None),
            other => panic!("expected RawEvent::Network, got {other:?}"),
        }
    }
}
