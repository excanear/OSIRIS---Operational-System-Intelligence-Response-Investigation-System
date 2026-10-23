//! eBPF net record → raw event conversion (OS-neutral, so tested everywhere).
//!
//! The kernel side (`osiris-ebpf`'s `net` program) emits one record per TCP
//! connect, accept or close. Each record is converted on its own: the
//! program can emit a CLOSE with no CONNECT/ACCEPT before it (a
//! simultaneous open, or an open record lost to a full ring buffer), so
//! nothing here pairs records or keeps per-connection state. Direction is
//! exact (Global Constraint #7): CONNECT is Outbound, ACCEPT is Inbound and
//! CLOSE carries the direction the program stored at open time — never a
//! port-range guess like the procfs poller's.
//!
//! `ktime_ns` is `bpf_ktime_get_ns()` (CLOCK_MONOTONIC); `timestamp_ns` is
//! it plus a realtime − monotonic offset the sensor resamples for every
//! record, exactly as the process backend does.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use osiris_ebpf::{resolve_exe, NetEvent, NetKind, AF_INET, DIR_INBOUND};
use osiris_sensor_api::{NetworkDirection, NetworkEventRaw, NetworkOperation, RawEventSource};

/// A record address as text: [`AF_INET`] from the first 4 bytes in dotted
/// form; anything else as IPv6 via `std::net::Ipv6Addr`, an IPv4-mapped
/// address (`::ffff:a.b.c.d`) rendered as plain IPv4 so a dual-stack
/// socket's peer matches what an IPv4 socket would report. `decode_net`
/// only admits `AF_INET` and `AF_INET6`.
pub fn render_addr(family: u16, addr: &[u8; 16]) -> String {
    if family == AF_INET {
        return Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string();
    }
    let v6 = Ipv6Addr::from(*addr);
    match v6.to_ipv4_mapped() {
        Some(v4) => v4.to_string(),
        None => v6.to_string(),
    }
}

/// `ktime_ns` (CLOCK_MONOTONIC) → wall-clock ns, clamped into `u64`.
fn wall_clock_ns(ktime_ns: u64, boot_wall_offset_ns: i128) -> u64 {
    let wall = i128::from(ktime_ns) + boot_wall_offset_ns;
    wall.clamp(0, i128::from(u64::MAX)) as u64
}

/// The connection's direction (Global Constraint #7): fixed by the hook for
/// an open record; for CLOSE, the value the program stored at open time
/// (`decode_net` only admits `DIR_OUTBOUND` and `DIR_INBOUND`).
fn direction(e: &NetEvent) -> NetworkDirection {
    match e.kind {
        NetKind::Connect => NetworkDirection::Outbound,
        NetKind::Accept => NetworkDirection::Inbound,
        NetKind::Close if e.direction == DIR_INBOUND => NetworkDirection::Inbound,
        NetKind::Close => NetworkDirection::Outbound,
    }
}

/// One decoded net record as the existing `NetworkEventRaw`, converted
/// without reference to any other record. `exe_path` is the
/// `<proc_root>/<pid>/exe` link when [`resolve_exe`] can tie it to the
/// record, else `""` (Global Constraint #9 step 3 for network records).
pub fn net_to_raw(e: &NetEvent, boot_wall_offset_ns: i128, proc_root: &Path) -> NetworkEventRaw {
    NetworkEventRaw {
        operation: match e.kind {
            NetKind::Connect => NetworkOperation::Connect,
            NetKind::Accept => NetworkOperation::Accept,
            NetKind::Close => NetworkOperation::Close,
        },
        local_addr: render_addr(e.family, &e.laddr),
        local_port: e.lport,
        remote_addr: render_addr(e.family, &e.raddr),
        remote_port: e.rport,
        proto: "tcp".to_string(),
        direction: direction(e),
        pid: Some(e.pid),
        uid: e.uid,
        exe_path: resolve_exe(proc_root, e.pid, e.exe, &e.comm).unwrap_or_default(),
        comm: e.comm.clone(),
        timestamp_ns: wall_clock_ns(e.ktime_ns, boot_wall_offset_ns),
        source: RawEventSource::Ebpf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_ebpf::{AF_INET6, DIR_OUTBOUND};

    fn v4(a: [u8; 4]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..4].copy_from_slice(&a);
        out
    }

    #[test]
    fn render_addr_cases() {
        assert_eq!(render_addr(AF_INET, &v4([127, 0, 0, 1])), "127.0.0.1");
        let mut loopback6 = [0u8; 16];
        loopback6[15] = 1;
        assert_eq!(render_addr(AF_INET6, &loopback6), "::1");
        let mut mapped = [0u8; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12..].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(render_addr(AF_INET6, &mapped), "1.2.3.4");
        let doc: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(render_addr(AF_INET6, &doc), "2001:db8::1");
    }

    fn event(kind: NetKind, direction: u8) -> NetEvent {
        NetEvent {
            kind,
            // No such pid under the fixture root.
            pid: 4242,
            uid: 1000,
            ktime_ns: 5_000,
            comm: "curl".to_string(),
            family: AF_INET,
            lport: 51_000,
            rport: 443,
            direction,
            laddr: v4([10, 0, 0, 5]),
            raddr: v4([93, 184, 216, 34]),
            exe: None,
        }
    }

    /// Every record converts on its own: the CLOSE below has no open record
    /// before it and still takes its direction from the record.
    #[test]
    fn net_to_raw_maps_kinds_and_direction() {
        let root = tempfile::tempdir().unwrap();
        let cases = [
            (
                NetKind::Connect,
                DIR_OUTBOUND,
                NetworkOperation::Connect,
                NetworkDirection::Outbound,
            ),
            (
                NetKind::Accept,
                DIR_INBOUND,
                NetworkOperation::Accept,
                NetworkDirection::Inbound,
            ),
            (
                NetKind::Close,
                DIR_INBOUND,
                NetworkOperation::Close,
                NetworkDirection::Inbound,
            ),
            (
                NetKind::Close,
                DIR_OUTBOUND,
                NetworkOperation::Close,
                NetworkDirection::Outbound,
            ),
        ];
        for (kind, dir, op, direction) in cases {
            let raw = net_to_raw(&event(kind, dir), 1_000, root.path());
            assert_eq!(raw.operation, op, "{kind:?}");
            assert_eq!(raw.direction, direction, "{kind:?}/{dir}");
            assert_eq!(raw.pid, Some(4242));
            assert_eq!(raw.uid, 1000);
            assert_eq!(raw.comm, "curl");
            assert_eq!(raw.local_addr, "10.0.0.5");
            assert_eq!(raw.local_port, 51_000);
            assert_eq!(raw.remote_addr, "93.184.216.34");
            assert_eq!(raw.remote_port, 443);
            assert_eq!(raw.exe_path, "");
            assert_eq!(raw.proto, "tcp");
            assert_eq!(raw.source, RawEventSource::Ebpf);
            assert_eq!(raw.timestamp_ns, 6_000);
        }
    }

    #[test]
    fn net_to_raw_clamps_the_timestamp_at_zero() {
        let root = tempfile::tempdir().unwrap();
        let raw = net_to_raw(&event(NetKind::Connect, DIR_OUTBOUND), -10_000, root.path());
        assert_eq!(raw.timestamp_ns, 0);
    }
}
