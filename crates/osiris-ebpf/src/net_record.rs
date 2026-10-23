//! Net record ABI shared with `bpf/net.bpf.c` (`bpf/net.h`), plus decoding.
//!
//! One fixed-size record per TCP connect, accept or close. The layout is
//! pinned by `net_layout_is_pinned` and mirrored by `_Static_assert`s in
//! `bpf/net.h`. Records arrive from the kernel ring buffer and are treated
//! as untrusted: decoding is length-checked, the family and direction are
//! validated and it never panics. It shares the header, [`DecodeError`] and
//! the read helpers with the process record (`record`).

use std::mem::size_of;

use crate::exe::{dev_to_user, ExeIdentity};
use crate::record::{c_string, read, DecodeError, RecordHeader, COMM_LEN};

pub const NET_SCHEMA_VERSION: u32 = 1;
pub const KIND_NET_CONNECT: u32 = 3;
pub const KIND_NET_ACCEPT: u32 = 4;
pub const KIND_NET_CLOSE: u32 = 5;
/// Address families (`include/linux/socket.h`), as stored in `family`.
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
/// Which hook opened the connection; CLOSE carries the value stored then.
pub const DIR_OUTBOUND: u8 = 1;
pub const DIR_INBOUND: u8 = 2;

/// One TCP connection event. Ports are in host byte order; addresses are
/// 16 bytes in network order, with an IPv4 address in the first 4 bytes
/// and the rest zero.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetRecord {
    pub hdr: RecordHeader,
    /// Owner tgid: the task that called `connect()`/`accept()`.
    pub pid: u32,
    pub uid: u32,
    /// `bpf_ktime_get_ns()` when the record was emitted.
    pub ktime_ns: u64,
    pub comm: [u8; COMM_LEN],
    pub family: u16,
    pub lport: u16,
    pub rport: u16,
    pub direction: u8,
    pub _pad: u8,
    pub laddr: [u8; 16],
    pub raddr: [u8; 16],
    /// Kernel-internal `dev_t` of the owner's `mm->exe_file` (0 = unknown).
    pub exe_dev: u32,
    pub _pad2: u32,
    /// The owner's `mm->exe_file` inode number (0 = unknown).
    pub exe_ino: u64,
}

/// Record kind of a [`NetEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetKind {
    Connect,
    Accept,
    Close,
}

/// Decoded net record (owned). Field meanings as in [`NetRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetEvent {
    pub kind: NetKind,
    pub pid: u32,
    pub uid: u32,
    pub ktime_ns: u64,
    pub comm: String,
    /// [`AF_INET`] or [`AF_INET6`].
    pub family: u16,
    pub lport: u16,
    pub rport: u16,
    /// [`DIR_OUTBOUND`] or [`DIR_INBOUND`].
    pub direction: u8,
    pub laddr: [u8; 16],
    pub raddr: [u8; 16],
    /// The owner's executable as the kernel saw it at connect/accept time;
    /// `None` when the record carries inode 0 (as for exec records).
    pub exe: Option<ExeIdentity>,
}

/// Decode one net ring-buffer record. Never panics on arbitrary input;
/// process kinds, unknown families and unknown directions are errors.
pub fn decode_net(bytes: &[u8]) -> Result<NetEvent, DecodeError> {
    if bytes.len() < size_of::<RecordHeader>() {
        return Err(DecodeError::ShorterThanHeader(bytes.len()));
    }
    let hdr: RecordHeader = read(bytes);
    if hdr.schema_version != NET_SCHEMA_VERSION {
        return Err(DecodeError::UnsupportedVersion(hdr.schema_version));
    }
    let kind = match hdr.kind {
        KIND_NET_CONNECT => NetKind::Connect,
        KIND_NET_ACCEPT => NetKind::Accept,
        KIND_NET_CLOSE => NetKind::Close,
        k => return Err(DecodeError::UnknownKind(k)),
    };
    let need = size_of::<NetRecord>();
    if bytes.len() < need {
        return Err(DecodeError::Truncated {
            kind: hdr.kind,
            got: bytes.len(),
            need,
        });
    }
    let r: NetRecord = read(bytes);
    if r.family != AF_INET && r.family != AF_INET6 {
        return Err(DecodeError::UnknownFamily(r.family));
    }
    if r.direction != DIR_OUTBOUND && r.direction != DIR_INBOUND {
        return Err(DecodeError::UnknownDirection(r.direction));
    }
    Ok(NetEvent {
        kind,
        pid: r.pid,
        uid: r.uid,
        ktime_ns: r.ktime_ns,
        comm: c_string(&r.comm, COMM_LEN),
        family: r.family,
        lport: r.lport,
        rport: r.rport,
        direction: r.direction,
        laddr: r.laddr,
        raddr: r.raddr,
        exe: (r.exe_ino != 0).then(|| ExeIdentity {
            dev: dev_to_user(r.exe_dev),
            ino: r.exe_ino,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{KIND_EXEC, KIND_EXIT};
    use std::mem::{offset_of, size_of, zeroed};

    fn as_bytes<T>(v: &T) -> Vec<u8> {
        // SAFETY: test-only view of a plain-old-data struct.
        unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }.to_vec()
    }

    fn v4_connect() -> NetRecord {
        // SAFETY: all-zero is a valid NetRecord.
        let mut r: NetRecord = unsafe { zeroed() };
        r.hdr = RecordHeader {
            schema_version: NET_SCHEMA_VERSION,
            kind: KIND_NET_CONNECT,
        };
        r.pid = 4242;
        r.uid = 1000;
        r.ktime_ns = 123_456;
        r.comm[..4].copy_from_slice(b"curl");
        r.family = AF_INET;
        r.lport = 51_000;
        r.rport = 443;
        r.direction = DIR_OUTBOUND;
        r.laddr[..4].copy_from_slice(&[10, 0, 0, 5]);
        r.raddr[..4].copy_from_slice(&[93, 184, 216, 34]);
        r.exe_dev = (8 << 20) | 1;
        r.exe_ino = 77;
        r
    }

    fn v6_accept() -> NetRecord {
        let mut r = v4_connect();
        r.hdr.kind = KIND_NET_ACCEPT;
        r.pid = 7;
        r.uid = 0;
        r.comm = [0; COMM_LEN];
        r.comm[..5].copy_from_slice(b"nginx");
        r.family = AF_INET6;
        r.lport = 8080;
        r.rport = 40_000;
        r.direction = DIR_INBOUND;
        r.laddr = [0; 16];
        r.laddr[15] = 1; // ::1
        r.raddr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        r.exe_dev = 0;
        r.exe_ino = 0;
        r
    }

    #[test]
    fn net_layout_is_pinned() {
        assert_eq!(NET_SCHEMA_VERSION, 1);
        assert_eq!(
            (KIND_NET_CONNECT, KIND_NET_ACCEPT, KIND_NET_CLOSE),
            (3, 4, 5)
        );
        assert_eq!((AF_INET, AF_INET6), (2, 10));
        assert_eq!((DIR_OUTBOUND, DIR_INBOUND), (1, 2));
        assert_eq!(size_of::<NetRecord>(), 96);
        assert_eq!(offset_of!(NetRecord, hdr), 0);
        assert_eq!(offset_of!(NetRecord, pid), 8);
        assert_eq!(offset_of!(NetRecord, uid), 12);
        assert_eq!(offset_of!(NetRecord, ktime_ns), 16);
        assert_eq!(offset_of!(NetRecord, comm), 24);
        assert_eq!(offset_of!(NetRecord, family), 40);
        assert_eq!(offset_of!(NetRecord, lport), 42);
        assert_eq!(offset_of!(NetRecord, rport), 44);
        assert_eq!(offset_of!(NetRecord, direction), 46);
        assert_eq!(offset_of!(NetRecord, _pad), 47);
        assert_eq!(offset_of!(NetRecord, laddr), 48);
        assert_eq!(offset_of!(NetRecord, raddr), 64);
        assert_eq!(offset_of!(NetRecord, exe_dev), 80);
        assert_eq!(offset_of!(NetRecord, _pad2), 84);
        assert_eq!(offset_of!(NetRecord, exe_ino), 88);
    }

    #[test]
    fn decode_net_v4_and_v6() {
        let e = decode_net(&as_bytes(&v4_connect())).unwrap();
        assert_eq!(e.kind, NetKind::Connect);
        assert_eq!((e.pid, e.uid, e.ktime_ns), (4242, 1000, 123_456));
        assert_eq!(e.comm, "curl");
        assert_eq!((e.family, e.lport, e.rport), (AF_INET, 51_000, 443));
        assert_eq!(e.direction, DIR_OUTBOUND);
        assert_eq!(e.laddr[..4], [10, 0, 0, 5]);
        assert_eq!(e.laddr[4..], [0; 12]);
        assert_eq!(e.raddr[..4], [93, 184, 216, 34]);
        assert_eq!(e.exe, Some(ExeIdentity { dev: 2049, ino: 77 }));

        let e = decode_net(&as_bytes(&v6_accept())).unwrap();
        assert_eq!(e.kind, NetKind::Accept);
        assert_eq!((e.pid, e.uid), (7, 0));
        assert_eq!(e.comm, "nginx");
        assert_eq!((e.family, e.lport, e.rport), (AF_INET6, 8080, 40_000));
        assert_eq!(e.direction, DIR_INBOUND);
        assert_eq!(e.laddr, v6_accept().laddr);
        assert_eq!(e.raddr, v6_accept().raddr);
        assert_eq!(e.exe, None);

        let mut r = v6_accept();
        r.hdr.kind = KIND_NET_CLOSE;
        assert_eq!(decode_net(&as_bytes(&r)).unwrap().kind, NetKind::Close);
        // Trailing bytes beyond the struct are tolerated.
        let mut b = as_bytes(&v4_connect());
        b.extend_from_slice(&[0xff; 8]);
        assert!(decode_net(&b).is_ok());
    }

    #[test]
    fn net_decode_rejects_bad_family_short_and_unknown_kind() {
        let mut r = v4_connect();
        r.family = 7;
        assert_eq!(
            decode_net(&as_bytes(&r)),
            Err(DecodeError::UnknownFamily(7))
        );

        let b = as_bytes(&v4_connect());
        assert_eq!(
            decode_net(&b[..95]),
            Err(DecodeError::Truncated {
                kind: KIND_NET_CONNECT,
                got: 95,
                need: 96
            })
        );
        assert_eq!(decode_net(&b[..3]), Err(DecodeError::ShorterThanHeader(3)));

        for kind in [9, KIND_EXEC, KIND_EXIT] {
            let mut r = v4_connect();
            r.hdr.kind = kind;
            assert_eq!(
                decode_net(&as_bytes(&r)),
                Err(DecodeError::UnknownKind(kind))
            );
        }

        let mut r = v4_connect();
        r.hdr.schema_version = 2;
        assert_eq!(
            decode_net(&as_bytes(&r)),
            Err(DecodeError::UnsupportedVersion(2))
        );

        let mut r = v4_connect();
        r.direction = 3;
        assert_eq!(
            decode_net(&as_bytes(&r)),
            Err(DecodeError::UnknownDirection(3))
        );

        // Arbitrary bytes never panic. Every third buffer carries a valid
        // header so the field checks past it are exercised too.
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
                buf[..4].copy_from_slice(&NET_SCHEMA_VERSION.to_ne_bytes());
                let kind = KIND_NET_CONNECT + (next() % 3) as u32;
                buf[4..8].copy_from_slice(&kind.to_ne_bytes());
            }
            let _ = decode_net(&buf);
        }
    }
}
