//! Linux `AF_PACKET` capture: socket setup and one-packet receive.
//!
//! The socket is created with protocol 0 (it receives nothing), gets the
//! [`crate::bpf::DNS_FILTER`] program and a receive timeout, and only then
//! is bound with `htons(ETH_P_ALL)` — so no unfiltered packet is ever
//! queued between `socket(2)` and `SO_ATTACH_FILTER`. The descriptor is an
//! [`OwnedFd`], closed on every path when dropped. `SO_TIMESTAMPNS` makes
//! each packet carry its kernel receive time, read with `recvmsg`.

use std::ffi::CString;
use std::fmt;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use crate::bpf::DNS_FILTER;

/// Receive timeout: bounds how long cancellation and engine ticks wait.
pub(crate) const RECV_TIMEOUT: Duration = Duration::from_millis(500);
/// Receive buffer size; the filter accepts at most 0xffff bytes.
pub(crate) const RECV_BUF: usize = 65536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CaptureError {
    Os { op: &'static str, errno: i32 },
    NoInterface(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os { op, errno } => write!(f, "AF_PACKET {op} failed: errno {errno}"),
            Self::NoInterface(name) => write!(f, "capture interface {name:?} not found"),
        }
    }
}

/// Result of one receive call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Recv {
    /// `len` bytes of L3 packet are in the buffer. `ts_wall_ns` is the
    /// kernel receive time (`SCM_TIMESTAMPNS`, wall clock); `None` when the
    /// control message was missing.
    Packet {
        len: usize,
        local_origin: bool,
        ts_wall_ns: Option<u64>,
    },
    /// Duplicate loopback copy; ignore.
    Skip,
    /// No packet within [`RECV_TIMEOUT`] (or interrupted).
    Timeout,
    /// Socket error (errno).
    Error(i32),
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn os_err(op: &'static str) -> CaptureError {
    CaptureError::Os { op, errno: errno() }
}

fn new_socket() -> Result<OwnedFd, i32> {
    // SAFETY: socket(2) takes no pointers; constant arguments.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: `fd` is a freshly created, valid descriptor owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Capability probe: open and immediately close an `AF_PACKET` socket.
pub(crate) fn probe() -> Result<(), i32> {
    new_socket().map(drop)
}

/// The filter program in kernel layout.
pub(crate) fn sock_filters() -> Vec<libc::sock_filter> {
    DNS_FILTER
        .iter()
        .map(|i| libc::sock_filter {
            code: i.code,
            jt: i.jt,
            jf: i.jf,
            k: i.k,
        })
        .collect()
}

fn ifindex(name: &str) -> Option<i32> {
    let c = CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string for the duration of the call.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    i32::try_from(idx).ok().filter(|&i| i != 0)
}

fn setsockopt<T>(fd: &OwnedFd, name: libc::c_int, value: &T) -> Result<(), ()> {
    // SAFETY: `value` is a valid, initialised `T` that outlives the call and
    // the length passed is exactly its size; the kernel copies it.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            name,
            (value as *const T).cast(),
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(())
    }
}

/// Decide what to do with a received packet (Ruling R4). On loopback every
/// packet is seen twice (outgoing then incoming): the outgoing copy is
/// skipped and the incoming one is still local-origin. Elsewhere, only
/// `PACKET_OUTGOING` packets were sent by this host. `None` = skip.
pub(crate) fn disposition(pkttype: u8, ifindex: i32, lo_ifindex: Option<i32>) -> Option<bool> {
    let on_lo = lo_ifindex == Some(ifindex);
    let outgoing = pkttype == libc::PACKET_OUTGOING;
    if on_lo && outgoing {
        None
    } else {
        Some(outgoing || on_lo)
    }
}

pub(crate) struct Capture {
    fd: OwnedFd,
    lo_ifindex: Option<i32>,
}

impl Capture {
    /// Open, filter and bind the capture socket; `interface` `None` = all.
    pub(crate) fn open(interface: Option<&str>) -> Result<Self, CaptureError> {
        let bind_index = match interface {
            Some(name) => ifindex(name).ok_or_else(|| CaptureError::NoInterface(name.into()))?,
            None => 0,
        };
        let fd = new_socket().map_err(|errno| CaptureError::Os {
            op: "socket",
            errno,
        })?;

        let mut prog = sock_filters();
        let fprog = libc::sock_fprog {
            len: prog.len() as libc::c_ushort,
            filter: prog.as_mut_ptr(),
        };
        setsockopt(&fd, libc::SO_ATTACH_FILTER, &fprog).map_err(|_| os_err("SO_ATTACH_FILTER"))?;

        let tv = libc::timeval {
            tv_sec: RECV_TIMEOUT.as_secs() as libc::time_t,
            tv_usec: RECV_TIMEOUT.subsec_micros() as libc::suseconds_t,
        };
        setsockopt(&fd, libc::SO_RCVTIMEO, &tv).map_err(|_| os_err("SO_RCVTIMEO"))?;

        // Kernel receive timestamps. Best effort: without them a packet falls
        // back to its processing time, which the sensor counts.
        let on: libc::c_int = 1;
        let _ = setsockopt(&fd, libc::SO_TIMESTAMPNS, &on);

        // SAFETY: `sockaddr_ll` is a plain C struct for which all-zero is valid.
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as libc::c_ushort;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = bind_index;
        // SAFETY: `sll` is a valid `sockaddr_ll` and the length is its size.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&sll as *const libc::sockaddr_ll).cast(),
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(os_err("bind"));
        }

        Ok(Self {
            fd,
            lo_ifindex: ifindex("lo"),
        })
    }

    /// Receive one packet into `buf`, blocking at most [`RECV_TIMEOUT`].
    pub(crate) fn recv(&self, buf: &mut [u8]) -> Recv {
        // SAFETY: `sockaddr_ll` is a plain C struct for which all-zero is valid.
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        // u64 elements keep the control buffer aligned for `cmsghdr`.
        let mut control = [0u64; CONTROL_WORDS];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: `msghdr` is a plain C struct for which all-zero is valid.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = (&mut sll as *mut libc::sockaddr_ll).cast();
        msg.msg_namelen = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = mem::size_of_val(&control) as _;
        // SAFETY: every pointer in `msg` (name, iovec, data and control
        // buffers) is valid and writable for the length given, for the whole
        // duration of the call.
        let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            let e = errno();
            return if e == libc::EAGAIN || e == libc::EWOULDBLOCK || e == libc::EINTR {
                Recv::Timeout
            } else {
                Recv::Error(e)
            };
        }
        let len = usize::try_from(n).unwrap_or(0).min(buf.len());
        match disposition(sll.sll_pkttype, sll.sll_ifindex, self.lo_ifindex) {
            Some(local_origin) => {
                let control_len = (msg.msg_controllen as usize).min(mem::size_of_val(&control));
                // SAFETY: `control` is a live, initialised buffer of at least
                // `control_len` bytes; u8 has no alignment requirement.
                let bytes = unsafe {
                    std::slice::from_raw_parts(control.as_ptr().cast::<u8>(), control_len)
                };
                Recv::Packet {
                    len,
                    local_origin,
                    ts_wall_ns: cmsg_timestamp_ns(bytes),
                }
            }
            None => Recv::Skip,
        }
    }
}

/// Size of the receive control buffer, in u64 words (room for a timestamp
/// and a few other messages).
const CONTROL_WORDS: usize = 16;

fn cmsg_align(len: usize) -> usize {
    let a = mem::size_of::<usize>();
    len.div_ceil(a) * a
}

/// Aligned header length: where a control message's data starts.
fn cmsg_hdr_len() -> usize {
    cmsg_align(mem::size_of::<libc::cmsghdr>())
}

/// Finds the `SCM_TIMESTAMPNS` control message in `control` (the bytes the
/// kernel wrote, `msg_controllen` long) and returns its wall-clock time in
/// ns since the epoch. Bounded and panic-free on any input; `None` when it
/// is absent, truncated or out of range.
pub(crate) fn cmsg_timestamp_ns(control: &[u8]) -> Option<u64> {
    let hdr_size = mem::size_of::<libc::cmsghdr>();
    let data_off = cmsg_hdr_len();
    let ts_size = mem::size_of::<libc::timespec>();
    let mut off = 0usize;
    while off.checked_add(hdr_size)? <= control.len() {
        // SAFETY: `off + size_of::<cmsghdr>() <= control.len()`, and the
        // read is unaligned, so any byte offset is fine.
        let h: libc::cmsghdr =
            unsafe { std::ptr::read_unaligned(control.as_ptr().add(off).cast()) };
        let len = h.cmsg_len as usize;
        if len < hdr_size || len > control.len() - off {
            return None;
        }
        if h.cmsg_level == libc::SOL_SOCKET
            && h.cmsg_type == libc::SCM_TIMESTAMPNS
            && len >= data_off + ts_size
        {
            // SAFETY: `off + data_off + size_of::<timespec>() <= off + len
            // <= control.len()`; the read is unaligned.
            let ts: libc::timespec =
                unsafe { std::ptr::read_unaligned(control.as_ptr().add(off + data_off).cast()) };
            let sec = u64::try_from(ts.tv_sec).ok()?;
            let nsec = u64::try_from(ts.tv_nsec)
                .ok()
                .filter(|&n| n < 1_000_000_000)?;
            return sec.checked_mul(1_000_000_000)?.checked_add(nsec);
        }
        off = off.checked_add(cmsg_align(len))?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf;

    #[test]
    fn cbpf_program_is_well_formed() {
        let prog = sock_filters();
        assert!(!prog.is_empty() && prog.len() <= 64);
        let last = prog[prog.len() - 1];
        assert_eq!(u32::from(last.code) & 0x07, libc::BPF_RET);
        // The first instruction is the ancillary protocol load.
        assert_eq!(prog[0].k, (libc::SKF_AD_OFF + libc::SKF_AD_PROTOCOL) as u32);
        for (i, ins) in prog.iter().enumerate() {
            if u32::from(ins.code) & 0x07 == libc::BPF_JMP {
                assert!(i + 1 + usize::from(ins.jt) < prog.len());
                assert!(i + 1 + usize::from(ins.jf) < prog.len());
            }
        }
    }

    #[test]
    fn local_bpf_constants_match_libc() {
        let pairs: [(u16, u32); 12] = [
            (bpf::BPF_LD, libc::BPF_LD),
            (bpf::BPF_LDX, libc::BPF_LDX),
            (bpf::BPF_JMP, libc::BPF_JMP),
            (bpf::BPF_RET, libc::BPF_RET),
            (bpf::BPF_H, libc::BPF_H),
            (bpf::BPF_B, libc::BPF_B),
            (bpf::BPF_ABS, libc::BPF_ABS),
            (bpf::BPF_IND, libc::BPF_IND),
            (bpf::BPF_MSH, libc::BPF_MSH),
            (bpf::BPF_JEQ, libc::BPF_JEQ),
            (bpf::BPF_JSET, libc::BPF_JSET),
            (bpf::BPF_K, libc::BPF_K),
        ];
        for (local, sys) in pairs {
            assert_eq!(u32::from(local), sys);
        }
        assert_eq!(bpf::SKF_AD_OFF, libc::SKF_AD_OFF);
        assert_eq!(bpf::SKF_AD_PROTOCOL, libc::SKF_AD_PROTOCOL);
        assert_eq!(bpf::ETH_P_IP, libc::ETH_P_IP as u32);
        assert_eq!(bpf::ETH_P_IPV6, libc::ETH_P_IPV6 as u32);
    }

    #[test]
    fn loopback_outgoing_copy_is_skipped() {
        let lo = Some(1);
        // lo: outgoing copy skipped, incoming copy kept as local-origin.
        assert_eq!(disposition(libc::PACKET_OUTGOING, 1, lo), None);
        assert_eq!(disposition(libc::PACKET_HOST, 1, lo), Some(true));
        // Other interfaces: outgoing is local, incoming is not.
        assert_eq!(disposition(libc::PACKET_OUTGOING, 2, lo), Some(true));
        assert_eq!(disposition(libc::PACKET_HOST, 2, lo), Some(false));
        // Unknown loopback index: nothing is skipped.
        assert_eq!(disposition(libc::PACKET_OUTGOING, 1, None), Some(true));
    }

    /// One control message (`level`, `kind`, `data`) laid out as the kernel
    /// does: header, data at the aligned offset, total padded to alignment.
    fn cmsg(level: libc::c_int, kind: libc::c_int, data: &[u8]) -> Vec<u8> {
        let hdr = cmsg_hdr_len();
        let len = hdr + data.len();
        let mut buf = vec![0u8; cmsg_align(len)];
        let h = libc::cmsghdr {
            cmsg_len: len as _,
            cmsg_level: level,
            cmsg_type: kind,
        };
        // SAFETY: `buf` holds at least `size_of::<cmsghdr>()` bytes.
        unsafe { std::ptr::write_unaligned(buf.as_mut_ptr().cast::<libc::cmsghdr>(), h) };
        buf[hdr..hdr + data.len()].copy_from_slice(data);
        buf
    }

    fn timespec_bytes(sec: i64, nsec: i64) -> Vec<u8> {
        let ts = libc::timespec {
            tv_sec: sec as libc::time_t,
            tv_nsec: nsec as _,
        };
        let mut b = vec![0u8; mem::size_of::<libc::timespec>()];
        // SAFETY: `b` is exactly `size_of::<timespec>()` bytes.
        unsafe { std::ptr::write_unaligned(b.as_mut_ptr().cast::<libc::timespec>(), ts) };
        b
    }

    #[test]
    fn cmsg_timestamp_parsed() {
        let ts = timespec_bytes(1_700_000_000, 123_456_789);
        let buf = cmsg(libc::SOL_SOCKET, libc::SCM_TIMESTAMPNS, &ts);
        assert_eq!(cmsg_timestamp_ns(&buf), Some(1_700_000_000_123_456_789));
        // After an unrelated control message.
        let mut two = cmsg(libc::SOL_IP, 8, &[1, 2, 3, 4]);
        two.extend_from_slice(&buf);
        assert_eq!(cmsg_timestamp_ns(&two), Some(1_700_000_000_123_456_789));
    }

    #[test]
    fn cmsg_timestamp_absent_or_malformed_is_none() {
        assert_eq!(cmsg_timestamp_ns(&[]), None);
        let other = cmsg(libc::SOL_SOCKET, libc::SCM_TIMESTAMP, &[0u8; 16]);
        assert_eq!(cmsg_timestamp_ns(&other), None);
        // Truncated: header claims more than the buffer holds.
        let mut cut = cmsg(
            libc::SOL_SOCKET,
            libc::SCM_TIMESTAMPNS,
            &timespec_bytes(1, 2),
        );
        cut.truncate(cmsg_hdr_len() + 4);
        assert_eq!(cmsg_timestamp_ns(&cut), None);
        // Out-of-range fields.
        let neg = cmsg(
            libc::SOL_SOCKET,
            libc::SCM_TIMESTAMPNS,
            &timespec_bytes(-1, 0),
        );
        assert_eq!(cmsg_timestamp_ns(&neg), None);
        let big = cmsg(
            libc::SOL_SOCKET,
            libc::SCM_TIMESTAMPNS,
            &timespec_bytes(1, 1_000_000_000),
        );
        assert_eq!(cmsg_timestamp_ns(&big), None);
        // A zero-length header must not loop forever.
        let zero = vec![0u8; 64];
        assert_eq!(cmsg_timestamp_ns(&zero), None);
        // Garbage of every short length.
        for n in 0..40 {
            assert_eq!(cmsg_timestamp_ns(&vec![0xff; n]), None);
        }
    }
}
