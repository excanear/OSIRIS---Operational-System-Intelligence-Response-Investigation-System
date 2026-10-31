//! DNS send record ABI shared with `bpf/dns.bpf.c` (`bpf/dns.h`), plus decoding.
//!
//! One fixed-size record per UDP send to port 53. The layout is pinned by
//! `dns_layout_is_pinned` and mirrored by `_Static_assert`s in `bpf/dns.h`.
//! Records arrive from the kernel ring buffer and are treated as untrusted:
//! decoding is length-checked, the family is validated and it never panics.
//! It shares the header, [`DecodeError`] and the read helpers with the
//! process record (`record`).

use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::exe::{dev_to_user, ExeIdentity};
pub use crate::net_record::{AF_INET, AF_INET6};
use crate::record::{c_string, read, DecodeError, RecordHeader, COMM_LEN};

pub const DNS_SCHEMA_VERSION: u32 = 1;
pub const KIND_DNS_SEND: u32 = 10;

/// One UDP send to port 53. Ports are in host byte order; addresses are 16
/// bytes in network order, an IPv4 address in the first 4 bytes and the rest
/// zero.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsRecord {
    pub hdr: RecordHeader,
    /// Sending task's tgid.
    pub pid: u32,
    /// Sending thread's pid.
    pub tid: u32,
    pub uid: u32,
    /// [`AF_INET`] or [`AF_INET6`].
    pub family: u16,
    pub lport: u16,
    /// `bpf_ktime_get_ns()` when the record was emitted.
    pub ktime_ns: u64,
    pub comm: [u8; COMM_LEN],
    /// Kernel-internal `dev_t` of the sender's `mm->exe_file` (0 = unknown).
    pub exe_dev: u32,
    /// Inode number of the sender's network namespace.
    pub netns_ino: u32,
    /// The sender's `mm->exe_file` inode number (0 = unknown).
    pub exe_ino: u64,
    pub rport: u16,
    pub _pad: u16,
    pub _pad2: u32,
    pub laddr: [u8; 16],
    pub raddr: [u8; 16],
}

/// Decoded DNS send record (owned).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSendEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub ktime_ns: u64,
    pub comm: String,
    /// `None` when the record carries inode 0.
    pub exe: Option<ExeIdentity>,
    pub netns_ino: u32,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

fn addr(family: u16, bytes: [u8; 16], port: u16) -> SocketAddr {
    let ip = if family == AF_INET {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(bytes))
    };
    SocketAddr::new(ip, port)
}

/// Decode one DNS ring-buffer record. Never panics on arbitrary input;
/// other kinds, unknown schema versions and unknown families are errors.
pub fn decode_dns(bytes: &[u8]) -> Result<DnsSendEvent, DecodeError> {
    if bytes.len() < size_of::<RecordHeader>() {
        return Err(DecodeError::ShorterThanHeader(bytes.len()));
    }
    let hdr: RecordHeader = read(bytes);
    if hdr.schema_version != DNS_SCHEMA_VERSION {
        return Err(DecodeError::UnsupportedVersion(hdr.schema_version));
    }
    if hdr.kind != KIND_DNS_SEND {
        return Err(DecodeError::UnknownKind(hdr.kind));
    }
    let need = size_of::<DnsRecord>();
    if bytes.len() < need {
        return Err(DecodeError::Truncated {
            kind: hdr.kind,
            got: bytes.len(),
            need,
        });
    }
    let r: DnsRecord = read(bytes);
    if r.family != AF_INET && r.family != AF_INET6 {
        return Err(DecodeError::UnknownFamily(r.family));
    }
    Ok(DnsSendEvent {
        pid: r.pid,
        tid: r.tid,
        uid: r.uid,
        ktime_ns: r.ktime_ns,
        comm: c_string(&r.comm, COMM_LEN),
        exe: (r.exe_ino != 0).then(|| ExeIdentity {
            dev: dev_to_user(r.exe_dev),
            ino: r.exe_ino,
        }),
        netns_ino: r.netns_ino,
        local: addr(r.family, r.laddr, r.lport),
        remote: addr(r.family, r.raddr, r.rport),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of, zeroed};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn as_bytes<T>(v: &T) -> Vec<u8> {
        // SAFETY: test-only view of a plain-old-data struct.
        unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }.to_vec()
    }

    fn v4() -> DnsRecord {
        // SAFETY: all-zero is a valid DnsRecord.
        let mut r: DnsRecord = unsafe { zeroed() };
        r.hdr = RecordHeader {
            schema_version: DNS_SCHEMA_VERSION,
            kind: KIND_DNS_SEND,
        };
        r.pid = 4242;
        r.tid = 4243;
        r.uid = 1000;
        r.family = AF_INET;
        r.lport = 41_000;
        r.rport = 53;
        r.ktime_ns = 99;
        r.comm[..4].copy_from_slice(b"curl");
        r.exe_dev = (8 << 20) | 1;
        r.exe_ino = 77;
        r.netns_ino = 4_026_531_840;
        r.laddr[..4].copy_from_slice(&[10, 0, 0, 5]);
        r.raddr[..4].copy_from_slice(&[127, 0, 0, 53]);
        r
    }

    fn v6() -> DnsRecord {
        let mut r = v4();
        r.family = AF_INET6;
        r.laddr = [0; 16];
        r.laddr[15] = 1;
        r.raddr = [0; 16];
        r.raddr[15] = 1;
        r.exe_dev = 0;
        r.exe_ino = 0;
        r
    }

    #[test]
    fn dns_layout_is_pinned() {
        assert_eq!(DNS_SCHEMA_VERSION, 1);
        assert_eq!(KIND_DNS_SEND, 10);
        assert_eq!(size_of::<DnsRecord>(), 104);
        assert_eq!(offset_of!(DnsRecord, hdr), 0);
        assert_eq!(offset_of!(DnsRecord, pid), 8);
        assert_eq!(offset_of!(DnsRecord, tid), 12);
        assert_eq!(offset_of!(DnsRecord, uid), 16);
        assert_eq!(offset_of!(DnsRecord, family), 20);
        assert_eq!(offset_of!(DnsRecord, lport), 22);
        assert_eq!(offset_of!(DnsRecord, ktime_ns), 24);
        assert_eq!(offset_of!(DnsRecord, comm), 32);
        assert_eq!(offset_of!(DnsRecord, exe_dev), 48);
        assert_eq!(offset_of!(DnsRecord, netns_ino), 52);
        assert_eq!(offset_of!(DnsRecord, exe_ino), 56);
        assert_eq!(offset_of!(DnsRecord, rport), 64);
        assert_eq!(offset_of!(DnsRecord, _pad), 66);
        assert_eq!(offset_of!(DnsRecord, _pad2), 68);
        assert_eq!(offset_of!(DnsRecord, laddr), 72);
        assert_eq!(offset_of!(DnsRecord, raddr), 88);
    }

    #[test]
    fn decode_dns_v4_and_v6() {
        let e = decode_dns(&as_bytes(&v4())).unwrap();
        assert_eq!((e.pid, e.tid, e.uid, e.ktime_ns), (4242, 4243, 1000, 99));
        assert_eq!(e.comm, "curl");
        assert_eq!(e.netns_ino, 4_026_531_840);
        assert_eq!(
            e.remote,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)), 53)
        );
        assert_eq!(
            e.local,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 41_000)
        );
        assert_eq!(e.exe, Some(ExeIdentity { dev: 2049, ino: 77 }));

        let e = decode_dns(&as_bytes(&v6())).unwrap();
        assert_eq!(
            e.remote,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53)
        );
        assert_eq!(
            e.local,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 41_000)
        );
        assert_eq!(e.exe, None);

        // Trailing bytes beyond the struct are tolerated.
        let mut b = as_bytes(&v4());
        b.extend_from_slice(&[0xff; 8]);
        assert!(decode_dns(&b).is_ok());
    }

    #[test]
    fn dns_decode_rejects_bad_input() {
        let b = as_bytes(&v4());
        assert_eq!(
            decode_dns(&b[..103]),
            Err(DecodeError::Truncated {
                kind: KIND_DNS_SEND,
                got: 103,
                need: 104
            })
        );
        assert_eq!(decode_dns(&b[..3]), Err(DecodeError::ShorterThanHeader(3)));

        let mut r = v4();
        r.hdr.kind = 9;
        assert_eq!(decode_dns(&as_bytes(&r)), Err(DecodeError::UnknownKind(9)));

        let mut r = v4();
        r.hdr.schema_version = 2;
        assert_eq!(
            decode_dns(&as_bytes(&r)),
            Err(DecodeError::UnsupportedVersion(2))
        );

        let mut r = v4();
        r.family = 7;
        assert_eq!(
            decode_dns(&as_bytes(&r)),
            Err(DecodeError::UnknownFamily(7))
        );

        // Arbitrary bytes never panic; every third buffer has a valid header.
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for i in 0..10_000u32 {
            let len = (next() % 128) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if i % 3 == 0 && len >= 8 {
                buf[..4].copy_from_slice(&DNS_SCHEMA_VERSION.to_ne_bytes());
                buf[4..8].copy_from_slice(&KIND_DNS_SEND.to_ne_bytes());
            }
            let _ = decode_dns(&buf);
        }
    }
}
